pub mod radare2;

pub trait AnalyzerBackend {
    fn analyze(&mut self) -> Result<(), &'static str>;
}
