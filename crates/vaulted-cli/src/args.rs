//! Command line surface.

use clap::{Args, Parser, Subcommand, ValueEnum};
use vaulted_core::{Algorithm, Normalization};

/// Environment variable holding the path to a keyring file.
pub const KEYRING_FILE_ENV: &str = "VAULTED_KEYRING_FILE";

/// Environment variable holding a keyring document inline.
pub const KEYRING_ENV: &str = "VAULTED_KEYRING";

/// Default keyring path used by `vaulted init` when none is given.
pub const DEFAULT_KEYRING_PATH: &str = "vaulted.keys.json";

#[derive(Debug, Parser)]
#[command(
    name = "vaulted",
    version,
    about = "Field-level encryption for databases",
    long_about = "Field-level encryption for databases.\n\n\
                  Manages keyrings, inspects stored values and re-encrypts them under a new key.\n\
                  Keys are never printed, and no command reads or writes a database."
)]
pub struct Cli {
    /// Path to the keyring file [env: VAULTED_KEYRING_FILE]
    ///
    /// If unset, VAULTED_KEYRING is used as an inline keyring document, and
    /// finally ./vaulted.keys.json.
    #[arg(long, short = 'k', global = true, value_name = "PATH")]
    pub keyring: Option<String>,

    /// Read a keyring file even if others can read it. Use sparingly.
    #[arg(long, global = true)]
    pub allow_insecure_keyring: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create a new keyring file with one freshly generated key version
    Init(InitArgs),

    /// Manage key versions
    #[command(subcommand)]
    Key(KeyCommand),

    /// Show what the keyring contains
    Status,

    /// Show the metadata of a stored value without decrypting it
    Inspect(InspectArgs),

    /// Compute the blind index used to look a value up
    BlindIndex(ValueArgs),

    /// Encrypt a value read from stdin
    Encrypt(ValueArgs),

    /// Decrypt a value read from stdin and print the plaintext
    Decrypt(FieldArgs),

    /// Re-encrypt stored values under the current primary key
    Rotate(FieldArgs),
}

#[derive(Debug, Subcommand)]
pub enum KeyCommand {
    /// Generate a new key version and add it to the keyring
    Create(KeyCreateArgs),

    /// List key versions. Key material is never shown
    List,

    /// Generate a new key version and make it primary
    ///
    /// This starts a rotation: new values use the new key immediately, while
    /// existing values keep naming the key they were written with. Use
    /// `vaulted rotate` to move those over.
    Rotate(KeyRotateArgs),
}

#[derive(Debug, Args)]
pub struct InitArgs {
    /// Overwrite an existing keyring file
    ///
    /// Refused by default: replacing a keyring makes every value encrypted
    /// with it unreadable, permanently.
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct KeyCreateArgs {
    /// Identifier for the new key version [default: next in the key-NNNN sequence]
    #[arg(long, value_name = "ID")]
    pub id: Option<String>,

    /// Make the new version primary, so new values are encrypted with it
    #[arg(long)]
    pub primary: bool,
}

#[derive(Debug, Args)]
pub struct KeyRotateArgs {
    /// Identifier for the new key version [default: next in the key-NNNN sequence]
    #[arg(long, value_name = "ID")]
    pub id: Option<String>,
}

#[derive(Debug, Args)]
pub struct InspectArgs {
    /// The serialized value, or `-` to read it from stdin
    #[arg(value_name = "CIPHERTEXT", default_value = "-")]
    pub value: String,
}

/// Arguments shared by the commands that operate on one field.
#[derive(Debug, Args)]
pub struct FieldArgs {
    /// Field name the value belongs to, for example users.email
    #[arg(long, short = 'f', value_name = "NAME")]
    pub field: String,

    /// Normalization applied before computing a blind index
    #[arg(long, value_enum, default_value_t = NormalizationArg::None)]
    pub normalization: NormalizationArg,

    /// Blind index length in bytes (8-32)
    #[arg(long, value_name = "N", default_value_t = 32)]
    pub blind_index_bytes: usize,

    /// Also compute a blind index for the field
    #[arg(long)]
    pub with_blind_index: bool,

    /// AEAD algorithm to encrypt with
    #[arg(long, value_enum, default_value_t = AlgorithmArg::Aes256Gcm)]
    pub algorithm: AlgorithmArg,
}

/// A field plus a value to operate on.
#[derive(Debug, Args)]
pub struct ValueArgs {
    #[command(flatten)]
    pub field: FieldArgs,

    /// The value. Prefer stdin: arguments are visible to other users via `ps`
    #[arg(long, value_name = "VALUE")]
    pub value: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum NormalizationArg {
    /// Use the value exactly as given
    None,
    /// Strip surrounding whitespace
    Trim,
    /// Lowercase
    Lowercase,
    /// Strip surrounding whitespace, then lowercase
    TrimLowercase,
    /// Email addresses: trim, then lowercase
    Email,
    /// Keep ASCII digits only
    DigitsOnly,
}

impl From<NormalizationArg> for Normalization {
    fn from(arg: NormalizationArg) -> Self {
        match arg {
            NormalizationArg::None => Normalization::None,
            NormalizationArg::Trim => Normalization::Trim,
            NormalizationArg::Lowercase => Normalization::Lowercase,
            NormalizationArg::TrimLowercase => Normalization::TrimLowercase,
            NormalizationArg::Email => Normalization::Email,
            NormalizationArg::DigitsOnly => Normalization::DigitsOnly,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AlgorithmArg {
    /// AES-256-GCM
    Aes256Gcm,
    /// XChaCha20-Poly1305
    Xchacha20Poly1305,
}

impl From<AlgorithmArg> for Algorithm {
    fn from(arg: AlgorithmArg) -> Self {
        match arg {
            AlgorithmArg::Aes256Gcm => Algorithm::Aes256Gcm,
            AlgorithmArg::Xchacha20Poly1305 => Algorithm::XChaCha20Poly1305,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn the_command_tree_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_a_representative_invocation() {
        let cli = Cli::parse_from([
            "vaulted",
            "--keyring",
            "/tmp/keys.json",
            "blind-index",
            "--field",
            "users.email",
            "--normalization",
            "email",
        ]);
        assert_eq!(cli.keyring.as_deref(), Some("/tmp/keys.json"));
        match cli.command {
            Command::BlindIndex(args) => {
                assert_eq!(args.field.field, "users.email");
                assert_eq!(args.field.normalization, NormalizationArg::Email);
                assert_eq!(args.field.blind_index_bytes, 32);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }
}
