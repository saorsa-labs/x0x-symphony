#![forbid(unsafe_code)]

use std::process::ExitCode;

use clap::Parser;
use x0x_symphony_bin::cli::{self, CommandLine};

#[tokio::main]
async fn main() -> ExitCode {
    match CommandLine::try_parse() {
        Ok(command_line) => run(command_line).await,
        Err(error) => {
            if let Err(print_error) = error.print() {
                eprintln!("failed to print clap error: {print_error}");
            }
            exit_code_from_i32(error.exit_code())
        }
    }
}

async fn run(command_line: CommandLine) -> ExitCode {
    match cli::run(command_line).await {
        Ok(output) => {
            print!("{}", output.stdout);
            eprint!("{}", output.stderr);
            ExitCode::from(output.exit_code)
        }
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(1)
        }
    }
}

fn exit_code_from_i32(value: i32) -> ExitCode {
    match u8::try_from(value) {
        Ok(code) => ExitCode::from(code),
        Err(_) => ExitCode::from(1),
    }
}
