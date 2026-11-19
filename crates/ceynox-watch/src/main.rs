//! ceynox-watch: see what a command, a package install or an AI coding agent
//! really does on your machine.
#![forbid(unsafe_code)]

mod baseline;
mod classify;
mod cli;
mod event;
mod export;
mod inspect;
mod render;
mod report;
mod run;
mod sensor;

use cli::Invocation;

fn main() {
    let code = match cli::parse(std::env::args_os().skip(1)) {
        Ok(Invocation::Help) => {
            println!("{}", cli::USAGE);
            0
        }
        Ok(Invocation::Version) => {
            println!("ceynox-watch {}", env!("CARGO_PKG_VERSION"));
            0
        }
        Ok(Invocation::Run { command, opts }) => run::run_command(command, opts),
        Ok(Invocation::Attach { scope, opts }) => run::attach(scope, opts),
        Ok(Invocation::View { file, follow, opts }) => run::view(&file, follow, opts),
        Ok(Invocation::Inspect { package, image, then, opts }) => inspect::run(&package, image.as_deref(), &then, opts),
        Ok(Invocation::Sensor { scope, buffer_mb }) => run::sensor_main(scope, buffer_mb),
        Ok(Invocation::Exec { command }) => run::exec_main(command),
        Err(msg) => {
            eprintln!("ceynox-watch: {msg}\nTry 'ceynox-watch --help'.");
            run::FAILURE
        }
    };
    std::process::exit(code);
}
