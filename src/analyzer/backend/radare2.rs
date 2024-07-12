use std::{collections::HashMap, path::PathBuf};

use r2pipe::{open_pipe, R2Pipe};
use serde::Deserialize;

use super::AnalyzerBackend;

#[derive(Deserialize)]
struct FunctionData {
    // function name
    name: String,
    // function offset
    offset: u64,
    // cyclomatic complexity
    cc: u64,
}

#[derive(Deserialize)]
struct FunctionReference {
    // type of reference
    r#type: String,
    // reference to address
    to: u64,
}

#[derive(Debug)]
struct Function {
    // function address
    offset: u64,
    // function name
    name: String,
    // cyclomatic complexity
    cc: u64,
    // list of addresses this function calls
    calls: Vec<u64>,
    // list of addresses that call this function
    callers: Vec<u64>,
    // number of times called
    x_f: u64,
    // function complexity index
    complex_f: u64,
}

impl Function {
    pub fn new(offset: u64) -> Self {
        Self {
            offset,
            name: String::new(),
            cc: 0,
            calls: Vec::new(),
            callers: Vec::new(),
            x_f: 0,
            complex_f: 0,
        }
    }
}

#[derive(Debug)]
pub struct ComplexityGroup {
    // complexity index
    complex_f: u64,
    // list of function addresses that have the same function complexity index
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
    radare2_pipe: R2Pipe,
    functions: HashMap<u64, Function>,
    complexity_groups: HashMap<u64, ComplexityGroup>,
}

impl Radare2AnalyzerBackend {
    pub fn build(firmware: &PathBuf) -> Result<Self, &'static str> {
        if !firmware.is_file() {
            return Err("Path does not exist or is not a file");
        }

        let radare2_pipe = match open_pipe!(firmware.to_str()) {
            Ok(radare2_pipe) => radare2_pipe,
            Err(_) => return Err("Could not open radare2 pipe"),
        };

        Ok(Self {
            radare2_pipe,
            functions: HashMap::new(),
            complexity_groups: HashMap::new(),
        })
    }

    fn set_functions(&mut self) -> Result<(), &'static str> {
        // analyze all functions
        match self.radare2_pipe.cmd("aaa") {
            Ok(_) => println!("Function information retrieved"),
            Err(_) => return Err("Command 'aaa' failed"),
        };
        // list functions and parse output
        let function_data: Vec<FunctionData> = match self.radare2_pipe.cmd("aflj") {
            Ok(output) => match serde_json::from_str(&output) {
                Ok(function_data) => function_data,
                Err(_) => return Err("Parsing ouput failed"),
            },
            Err(_) => return Err("Command 'aflj' failed"),
        };

        let mut functions: HashMap<u64, Function> = HashMap::new();
        for data in function_data {
            // if function exists at this point, it was added for function references
            if !functions.contains_key(&data.offset) {
                let function = Function::new(data.offset);
                functions.insert(data.offset, function);
            }
            // seek to address of function
            match self.radare2_pipe.cmd(&format!("s {}", data.offset)) {
                Ok(_) => println!("Extracting function calls of {}", data.name),
                Err(_) => return Err("Command 's' failed"),
            };
            // list function references and parse output
            let function_references: Vec<FunctionReference> = match self.radare2_pipe.cmd("afxj") {
                Ok(output) => match serde_json::from_str(&output) {
                    Ok(function_references) => function_references,
                    Err(_) => return Err("Parsing ouput failed"),
                },
                Err(_) => return Err("Command 'afxj' failed"),
            };
            // set references of calling function and called functions
            let mut calls: Vec<u64> = Vec::new();
            for reference in function_references {
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
            // fill function with data
            let function = functions.get_mut(&data.offset).unwrap();
            function.name = data.name.clone();
            function.cc = data.cc;
            function.calls.append(&mut calls);
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
        let mut complexity_groups: HashMap<u64, ComplexityGroup> = HashMap::new();
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

    fn calculate_sensitivity_function_call_index(&self) {}

    fn calculate_memory_operation_count(&self) {}

    fn vulnerability_feature_ranking(&self) {
        self.calculate_sensitivity_function_call_index();
        self.calculate_memory_operation_count();
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

        #[cfg(debug_assertions)]
        for function in self.functions.values() {
            println!("{:?}", function);
        }
        #[cfg(debug_assertions)]
        for group in self.complexity_groups.values() {
            println!("{:?}", group);
        }

        Ok(())
    }
}
