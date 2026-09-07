//! `vaulted` — command line tooling for field-level encryption.
//!
//! Everything here operates on keyrings and on values you hand it. No command
//! connects to a database: schema migration and bulk re-encryption need to know
//! about your tables, and that belongs in a later version rather than in a tool
//! that would have to guess.

#![forbid(unsafe_code)]

mod args;
mod commands;
mod context;

use std::process::ExitCode;

use clap::Parser;

use crate::args::{Cli, Command, KeyCommand};

fn main() -> ExitCode {
    let cli = Cli::parse();

    match dispatch(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("vaulted: {err}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(cli: &Cli) -> context::Result<()> {
    match &cli.command {
        Command::Init(args) => commands::init(cli, args),
        Command::Key(KeyCommand::Create(args)) => commands::key_create(cli, args),
        Command::Key(KeyCommand::List) => commands::key_list(cli),
        Command::Key(KeyCommand::Rotate(args)) => commands::key_rotate(cli, args),
        Command::Status => commands::status(cli),
        Command::Inspect(args) => commands::inspect(args),
        Command::BlindIndex(args) => commands::blind_index(cli, args),
        Command::Encrypt(args) => commands::encrypt(cli, args),
        Command::Decrypt(args) => commands::decrypt(cli, args),
        Command::Rotate(args) => commands::rotate(cli, args),
    }
}
