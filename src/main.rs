use std::{fs::File, io::Write, process};

use streamline::{
    analyzer::{backend::radare2::Radare2AnalyzerBackend, Analyzer},
    cli::{self, StreamlineCommands},
};

fn main() {
    let cli = cli::parse_args();

    match &cli.command {
        StreamlineCommands::Analyze {
            firmware,
            sensitive_functions,
        } => {
            let backend = Radare2AnalyzerBackend::build(firmware, sensitive_functions)
                .unwrap_or_else(|err| {
                    eprintln!("Error creating analyzer backend: {err}");
                    process::exit(1);
                });
            let mut analyzer = Analyzer::new(backend);
            analyzer.analyze().unwrap_or_else(|err| {
                eprintln!("Error during analysis: {err}");
                process::exit(1);
            });
            let target_functions = analyzer.export();
            let yaml_target_functions =
                serde_yml::to_string(&target_functions).unwrap_or_else(|err| {
                    eprintln!("Error serializing target functions: {err}");
                    process::exit(1);
                });
            let mut target_file = File::create("target_functions.yml").unwrap_or_else(|err| {
                eprintln!("Error creating/opening target file: {err}");
                process::exit(1);
            });
            target_file
                .write_all(yaml_target_functions.as_bytes())
                .unwrap_or_else(|err| {
                    eprintln!("Error writing target functions to target file: {err}");
                    process::exit(1);
                });
        }
        StreamlineCommands::Fuzz {} => {}
    }
}
