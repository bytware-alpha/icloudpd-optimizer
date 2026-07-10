use std::process::ExitCode;

fn main() -> ExitCode {
    match icloudpd_optimizer::cli::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
