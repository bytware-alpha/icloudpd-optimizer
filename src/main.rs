use std::process::ExitCode;

fn main() -> ExitCode {
    match icloudpd_raw_compactor::cli::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
