use serde::Serialize;

pub mod radare2;

#[derive(Serialize)]
pub struct TargetFunction {
    // function address
    address: u64,
    // function name
    name: String,
    // function complexity index
    complexity: u64,
    // function vulnerability feature index
    vulnerability: f64,
}

impl TargetFunction {
    pub fn new(address: u64, name: String, complexity: u64, vulnerability: f64) -> Self {
        Self {
            address,
            name,
            complexity,
            vulnerability,
        }
    }
}

pub trait AnalyzerBackend {
    fn analyze(&mut self) -> Result<(), &'static str>;
    fn export(&self) -> Vec<TargetFunction>;
}
