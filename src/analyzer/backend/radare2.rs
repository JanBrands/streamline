use std::{
    collections::{BTreeMap, HashMap},
    fs,
    path::PathBuf,
};

use r2pipe::{open_pipe, R2Pipe};
use serde::Deserialize;

use super::{AnalyzerBackend, TargetFunction};

#[derive(Deserialize)]
struct JSONFunctionData {
    /// function name
    name: String,
    /// function offset
    offset: u64,
    /// function size in byte
    size: u64,
    /// cyclomatic complexity
    cc: u64,
}

#[derive(Deserialize)]
struct JSONFunctionReference {
    /// type of reference
    r#type: String,
    /// reference to address
    to: u64,
}

#[derive(Deserialize, Debug)]
struct JSONOperation {
    /// operation address
    addr: u64,
    /// operation type
    r#type: String,
}

#[derive(Debug)]
struct Function {
    /// function address
    offset: u64,
    /// function name
    name: String,
    /// function size in byte
    size: u64,
    /// cyclomatic complexity
    cc: u64,
    /// list of addresses this function calls
    calls: Vec<u64>,
    /// list of addresses that call this function
    callers: Vec<u64>,
    /// number of times called
    x_f: u64,
    /// function complexity index
    complex_f: u64,
    /// sensitivity function call index
    s_f: f64,
    /// list of operations
    operation_list: Vec<JSONOperation>,
    /// number of memory operations
    p_f: f64,
    /// vulnerability feature index
    vulnerability_f: f64,
}

impl Function {
    pub fn new(offset: u64) -> Self {
        Self {
            offset,
            name: String::new(),
            size: 0,
            cc: 0,
            calls: Vec::new(),
            callers: Vec::new(),
            x_f: 0,
            complex_f: 0,
            s_f: 0.0,
            operation_list: Vec::new(),
            p_f: 0.0,
            vulnerability_f: 0.0,
        }
    }
}

#[derive(Debug)]
pub struct ComplexityGroup {
    /// complexity index
    complex_f: u64,
    /// list of function addresses that have the same function complexity index
    functions: Vec<u64>,
}

impl ComplexityGroup {
    pub fn new(complex_f: u64) -> Self {
        Self {
            complex_f,
            functions: Vec::new(),
        }
    }
}

pub struct Radare2AnalyzerBackend {
    /// map of addresses of analyzed functions (key) with their data (value)
    functions: HashMap<u64, Function>,
    /// map of complexity indexes (key) with their complexity groups (value)
    complexity_groups: BTreeMap<u64, ComplexityGroup>,
    /// map of names of sensitive functions (key) with their weights (value)
    sensitive_functions: HashMap<String, f64>,
    /// pipe to communicate with radare2
    radare2_pipe: R2Pipe,
}

impl Radare2AnalyzerBackend {
    pub fn build(firmware: &PathBuf, sensitive_functions: &PathBuf) -> Result<Self, &'static str> {
        if !firmware.is_file() {
            return Err("Path of firmware file does not exist or is not a file");
        }
        if !sensitive_functions.is_file() {
            return Err("Path of sensitive function file does not exist or is not a file");
        }
        let file_content = match fs::read_to_string(sensitive_functions) {
            Ok(file_content) => file_content,
            Err(_) => return Err("Reading file with sensitive functions failed"),
        };
        let sensitive_functions: HashMap<String, f64> = match serde_yml::from_str(&file_content) {
            Ok(yaml_sensitive_functions) => yaml_sensitive_functions,
            Err(_) => return Err("Parsing file with sensitive functions failed"),
        };
        let radare2_pipe = match open_pipe!(firmware.to_str()) {
            Ok(radare2_pipe) => radare2_pipe,
            Err(_) => return Err("Could not open radare2 pipe"),
        };

        Ok(Self {
            functions: HashMap::new(),
            complexity_groups: BTreeMap::new(),
            sensitive_functions,
            radare2_pipe,
        })
    }

    fn set_functions(&mut self) -> Result<(), &'static str> {
        // analyze all functions
        match self.radare2_pipe.cmd("aaa") {
            Ok(_) => println!("Functions analyzed. Extracting data..."),
            Err(_) => return Err("Command 'aaa' failed"),
        };
        // list functions and parse output
        let json_function_data: Vec<JSONFunctionData> = match self.radare2_pipe.cmd("aflj") {
            Ok(output) => match serde_json::from_str(&output) {
                Ok(json_function_data) => json_function_data,
                Err(_) => return Err("Parsing ouput of command 'aflj' failed"),
            },
            Err(_) => return Err("Command 'aflj' failed"),
        };
        let mut functions: HashMap<u64, Function> = HashMap::new();
        for data in json_function_data {
            // if function exists at this point, it was added for function references
            if !functions.contains_key(&data.offset) {
                let function = Function::new(data.offset);
                functions.insert(data.offset, function);
            }
            // seek to address of function
            match self.radare2_pipe.cmd(&format!("s {}", data.offset)) {
                Ok(_) => println!("Extracting data of {}", data.name),
                Err(_) => return Err("Command 's' failed"),
            };
            // list function references and parse output
            let json_function_references: Vec<JSONFunctionReference> =
                match self.radare2_pipe.cmd("afxj") {
                    Ok(output) => match serde_json::from_str(&output) {
                        Ok(json_function_references) => json_function_references,
                        Err(_) => return Err("Parsing ouput of command 'afxj' failed"),
                    },
                    Err(_) => return Err("Command 'afxj' failed"),
                };
            // set references of calling function and called functions
            let mut calls: Vec<u64> = Vec::new();
            for reference in json_function_references {
                if reference.r#type == "CALL" {
                    calls.push(reference.to);
                    if !functions.contains_key(&reference.to) {
                        let function = Function::new(reference.to);
                        functions.insert(reference.to, function);
                    }
                    let called_function = functions.get_mut(&reference.to).unwrap();
                    called_function.callers.push(data.offset);
                }
            }
            // list operations and parse output
            let mut json_operation_list: Vec<JSONOperation> =
                match self.radare2_pipe.cmd(format!("aOj {}", data.size).as_str()) {
                    Ok(output) => match serde_json::from_str(&output) {
                        Ok(json_operation_list) => json_operation_list,
                        Err(_) => return Err("Parsing output of command 'aOj' failed"),
                    },
                    Err(_) => return Err("Command 'aOj' failed"),
                };
            // fill function with data
            let function = functions.get_mut(&data.offset).unwrap();
            function.name = data.name.clone();
            function.size = data.size;
            function.cc = data.cc;
            function.calls.append(&mut calls);
            function.operation_list.append(&mut json_operation_list);
        }
        self.functions = functions;

        Ok(())
    }

    fn calculate_reference_relationship(&mut self) {
        for function in self.functions.values_mut() {
            function.x_f = function.callers.len() as u64;
        }
    }

    fn calculate_complexity_index(&mut self) {
        for function in self.functions.values_mut() {
            let cc = function.cc as f64;
            let complex_f = cc.ln().floor() as u64 + function.x_f;
            function.complex_f = complex_f;
        }
    }

    fn group_functions(&mut self) {
        let mut complexity_groups: BTreeMap<u64, ComplexityGroup> = BTreeMap::new();
        for function in self.functions.values() {
            if function.complex_f > 0 {
                if !complexity_groups.contains_key(&function.complex_f) {
                    let complexity_group = ComplexityGroup::new(function.complex_f);
                    complexity_groups.insert(function.complex_f, complexity_group);
                }
                let complexity_group = complexity_groups.get_mut(&function.complex_f).unwrap();
                complexity_group.functions.push(function.offset);
            }
        }
        self.complexity_groups = complexity_groups;
    }

    fn complexity_grouping(&mut self) {
        self.calculate_reference_relationship();
        self.calculate_complexity_index();
        self.group_functions();
    }

    fn calculate_sensitivity_function_call_index(&mut self) {
        let mut function_sensitivities: HashMap<u64, f64> = HashMap::new();
        for function in self.functions.values() {
            let mut s_f = 0.0;
            for call in &function.calls {
                let called_function = match self.functions.get(&call) {
                    Some(called_function) => called_function,
                    None => continue,
                };
                // get function name after last "."
                let function_name = match called_function.name.split(".").last() {
                    Some(function_name) => function_name,
                    None => &function.name,
                };
                for sensitive_function in &self.sensitive_functions {
                    // check if name of called function matches name of sensitive function
                    if function_name == sensitive_function.0 {
                        // add weight of sensitive function
                        s_f += sensitive_function.1;
                    }
                }
            }
            function_sensitivities.insert(function.offset, s_f);
        }
        for function_sensitivity in function_sensitivities {
            let function = match self.functions.get_mut(&function_sensitivity.0) {
                Some(function) => function,
                None => continue,
            };
            // set sensitive function call index
            function.s_f = function_sensitivity.1;
        }
    }

    fn calculate_memory_operation_count(&mut self) {
        // operation types that indicate a memory operation
        let memory_operation_types = vec!["load", "store"];
        for function in self.functions.values_mut() {
            let mut memory_operation_count = 0;
            for operation in &function.operation_list {
                if memory_operation_types
                    .iter()
                    .any(|t| &operation.r#type == t)
                {
                    memory_operation_count += 1;
                }
            }
            let p_f = memory_operation_count as f64 / function.operation_list.len() as f64;
            function.p_f = p_f;
        }
    }

    fn calculate_vulnerability_feature_index(&mut self) {
        for function in self.functions.values_mut() {
            let vulnerabilty_f = function.s_f + function.p_f;
            function.vulnerability_f = vulnerabilty_f;
        }
    }

    fn rank_functions(&mut self) {
        for group in self.complexity_groups.values_mut() {
            group.functions.sort_by(|a, b| {
                let vulnerybility_f_a = match self.functions.get(a) {
                    Some(function) => function.vulnerability_f,
                    None => 0.0 as f64,
                };
                let vulnerybility_f_b = match self.functions.get(b) {
                    Some(function) => function.vulnerability_f,
                    None => 0.0 as f64,
                };
                vulnerybility_f_b.total_cmp(&vulnerybility_f_a)
            });
        }
    }

    fn vulnerability_feature_ranking(&mut self) {
        self.calculate_sensitivity_function_call_index();
        self.calculate_memory_operation_count();
        self.calculate_vulnerability_feature_index();
        self.rank_functions();
    }
}

impl Drop for Radare2AnalyzerBackend {
    fn drop(&mut self) {
        self.radare2_pipe.close();
    }
}

impl AnalyzerBackend for Radare2AnalyzerBackend {
    fn analyze(&mut self) -> Result<(), &'static str> {
        self.set_functions()?;
        self.complexity_grouping();
        self.vulnerability_feature_ranking();

        Ok(())
    }

    /// Return
    fn export(&self) -> Vec<TargetFunction> {
        let mut target_functions = Vec::new();
        for group in self.complexity_groups.values() {
            for target_function_address in &group.functions {
                let function = match self.functions.get(&target_function_address) {
                    Some(function) => function,
                    None => continue,
                };
                if function.vulnerability_f > 0.0 {
                    let target_function = TargetFunction::new(
                        function.offset,
                        function.name.clone(),
                        function.complex_f,
                        function.vulnerability_f,
                    );
                    target_functions.push(target_function);
                    break;
                }
            }
        }
        target_functions
    }
}
