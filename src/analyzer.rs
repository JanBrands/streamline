use backend::{AnalyzerBackend, TargetFunction};

pub mod backend;

pub struct Analyzer<T: AnalyzerBackend> {
    backend: T,
}

impl<T: AnalyzerBackend> Analyzer<T> {
    pub fn new(backend: T) -> Self {
        Self { backend }
    }

    pub fn analyze(&mut self) -> Result<(), &'static str> {
        self.backend.analyze()
    }

    pub fn export(&self) -> Vec<TargetFunction> {
        self.backend.export()
    }
}
