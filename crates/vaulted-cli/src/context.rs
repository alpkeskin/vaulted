//! Locating and loading the keyring, plus the CLI's error type.

use std::fmt;
use std::path::PathBuf;

use vaulted_core::{LocalKeyProvider, Vault};

use crate::args::{Cli, FieldArgs, DEFAULT_KEYRING_PATH, KEYRING_ENV, KEYRING_FILE_ENV};

/// Result type used by every command.
pub type Result<T> = std::result::Result<T, Error>;

/// A failure worth reporting to the operator.
#[derive(Debug)]
pub enum Error {
    /// Something in the library failed.
    Vaulted(vaulted_core::Error),
    /// Reading stdin or writing stdout failed.
    Io(std::io::Error),
    /// The command was used in a way that cannot work.
    Usage(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // Library errors are written to be safe to show: they never carry
            // plaintext or key material.
            Self::Vaulted(err) => write!(f, "{err}"),
            Self::Io(err) => write!(f, "{err}"),
            Self::Usage(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for Error {}

impl From<vaulted_core::Error> for Error {
    fn from(err: vaulted_core::Error) -> Self {
        Self::Vaulted(err)
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

/// Where the keyring comes from.
#[derive(Debug, Clone)]
pub enum KeyringSource {
    /// A JSON keyring file.
    File(PathBuf),
    /// A JSON keyring held in an environment variable.
    Env(String),
}

impl fmt::Display for KeyringSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File(path) => write!(f, "{}", path.display()),
            Self::Env(var) => write!(f, "${var}"),
        }
    }
}

impl KeyringSource {
    /// Resolves the keyring location.
    ///
    /// In order: `--keyring`, `$VAULTED_KEYRING_FILE`, an inline
    /// `$VAULTED_KEYRING` document, then `./vaulted.keys.json`.
    pub fn resolve(cli: &Cli) -> Self {
        if let Some(path) = &cli.keyring {
            return Self::File(PathBuf::from(path));
        }
        if let Ok(path) = std::env::var(KEYRING_FILE_ENV) {
            if !path.is_empty() {
                return Self::File(PathBuf::from(path));
            }
        }
        if std::env::var_os(KEYRING_ENV).is_some() {
            return Self::Env(KEYRING_ENV.to_string());
        }
        Self::File(PathBuf::from(DEFAULT_KEYRING_PATH))
    }

    /// The file path, when the keyring lives in a file.
    pub fn path(&self) -> Option<&PathBuf> {
        match self {
            Self::File(path) => Some(path),
            Self::Env(_) => None,
        }
    }
}

/// Loads the key provider named by the command line and environment.
pub fn load_provider(cli: &Cli) -> Result<(LocalKeyProvider, KeyringSource)> {
    let source = KeyringSource::resolve(cli);
    let provider = match &source {
        KeyringSource::File(path) => {
            if !path.exists() {
                return Err(Error::Usage(format!(
                    "no keyring at {}; create one with `vaulted init`",
                    path.display()
                )));
            }
            if cli.allow_insecure_keyring {
                LocalKeyProvider::load_file_ignoring_permissions(path)?
            } else {
                LocalKeyProvider::load_file(path)?
            }
        }
        KeyringSource::Env(var) => LocalKeyProvider::from_env(var)?,
    };
    Ok((provider, source))
}

/// Builds a vault for a single field, as the value-level commands need.
///
/// `force_blind_index` is set by commands whose whole job is producing an
/// index, so `--with-blind-index` is not required there.
pub fn vault_for_field(
    provider: LocalKeyProvider,
    args: &FieldArgs,
    force_blind_index: bool,
) -> Result<Vault> {
    use vaulted_core::{BlindIndexConfig, FieldConfig};

    let mut config = FieldConfig::new(&args.field)?
        .with_normalization(args.normalization.into())
        .with_algorithm(args.algorithm.into());

    // Normalization only matters for indexing, so it is only meaningful when a
    // blind index is being produced; declaring the index is what turns it on.
    if args.with_blind_index || force_blind_index {
        config = config
            .with_blind_index(BlindIndexConfig::new().with_output_bytes(args.blind_index_bytes)?);
    }

    Ok(Vault::builder()
        .key_provider(provider)
        .algorithm(args.algorithm.into())
        .field(config)
        .build()?)
}
