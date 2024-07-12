use std::process;

use streamline::{
    analyzer::{backend::radare2::Radare2AnalyzerBackend, Analyzer},
    cli::{self, StreamlineCommands},
};

fn main() {
    let cli = cli::parse_args();

    match &cli.command {
        StreamlineCommands::Analyze { firmware } => {
            let backend = Radare2AnalyzerBackend::build(firmware).unwrap_or_else(|err| {
                eprintln!("Error creating analyzer backend: {err}");
                process::exit(1);
            });
            let mut analyzer = Analyzer::new(backend);
            analyzer.analyze().unwrap_or_else(|err| {
                eprintln!("Error during analysis: {err}");
                process::exit(1);
            });
            analyzer.export();
        }
        StreamlineCommands::Fuzz {} => {}
    }
}
