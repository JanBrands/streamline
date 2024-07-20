use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "Streamline")]
#[command(about = "Directed greybox fuzzing of monolithic firmware")]
#[command(version)]
pub struct StreamlineOptions {
    #[command(subcommand)]
    pub command: StreamlineCommands,
}

#[derive(Subcommand)]
pub enum StreamlineCommands {
    /// Analyze firmware for potentially vulnerable target locations
    Analyze {
        /// Path to the firmware to analyze
        #[arg(short, long, value_name = "FILE")]
        firmware: PathBuf,
        /// Path to a YAML file with sensitive functions
        #[arg(short, long, value_name = "FILE")]
        sensitive_functions: PathBuf,
    },

    /// Emulate and fuzz firmware
    Fuzz {},
}

pub fn parse_args() -> StreamlineOptions {
    StreamlineOptions::parse()
}
