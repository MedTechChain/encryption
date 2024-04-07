extern crate paillier;
extern crate serde_json;
use clap::{Parser, Subcommand};
use paillier::*;
use serde_json::json;

/// Struct representing command-line arguments.
#[derive(Parser, Debug)]
#[command(author = None, version, about = None, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generates a new keypair and prints them.
    ///
    /// Parameters:
    /// - `bit_length`: The bit length for the generated keys.
    Keygen {
        #[arg(short, long)]
        bit_length: usize,
    },

    /// Encrypts a given plaintext with the provided encryption key.
    ///
    /// Parameters:
    /// - `plaintext`: The plaintext to encrypt.
    /// - `ek`: The encryption key in JSON format.
    Encrypt {
        #[arg(short, long)]
        plaintext: u64,
        #[arg(short, long)]
        ek: String,
    },

    /// Decrypts a given ciphertext with the provided decryption key.
    ///
    /// Parameters:
    /// - `ciphertext`: The ciphertext to decrypt.
    /// - `dk`: The decryption key in JSON format.
    Decrypt {
        #[arg(short, long)]
        ciphertext: String,
        #[arg(short, long)]
        dk: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Keygen { bit_length } => {
            let (ek, dk) = generate_keys(*bit_length);
            let response = json!({
                "encryptionKey": serde_json::to_string(&ek).expect("Failed to serialize EncryptionKey"),
                "decryptionKey": serde_json::to_string(&dk).expect("Failed to serialize DecryptionKey")
            });
            println!("{}", response);
        }
        Commands::Encrypt { plaintext, ek } => {
            let ek: EncryptionKey =
                serde_json::from_str(ek).expect("Failed to deserialize EncryptionKey");
            let ciphertext = encrypt(&ek, *plaintext);
            let response = json!({
                "ciphertext": serde_json::to_string(&ciphertext).expect("Failed to serialize ciphertext"),
            });
            println!("{}", response);
        }
        Commands::Decrypt { ciphertext, dk } => {
            let dk: DecryptionKey =
                serde_json::from_str(dk).expect("Failed to deserialize DecryptionKey");
            let ciphertext: EncodedCiphertext<u64> =
                serde_json::from_str(ciphertext).expect("Failed to deserialize ciphertext");
            let plaintext = decrypt(&dk, ciphertext);
            let response = json!({
                "plaintext": plaintext,
            });
            println!("{}", response);
        }
    }
}

/// Generates a pair of encryption and decryption keys.
///
/// Parameters:
/// - `bit_length`: The bit length for the generated keys.
///
/// Returns:
/// A tuple containing the encryption key (`EncryptionKey`) and the decryption key (`DecryptionKey`).
fn generate_keys(bit_length: usize) -> (EncryptionKey, DecryptionKey) {
    let (ek, dk) = Paillier::keypair_with_modulus_size(bit_length).keys();

    (ek, dk)
}

/// Encrypts a plaintext message.
///
/// Parameters:
/// - `ek`: A reference to the encryption key.
/// - `m`: The plaintext message as a `u64`.
///
/// Returns:
/// The encrypted message as an `EncodedCiphertext<u64>`.
fn encrypt(ek: &EncryptionKey, m: u64) -> EncodedCiphertext<u64> {
    Paillier::encrypt(ek, m)
}

/// Decrypts a ciphertext message.
///
/// Parameters:
/// - `dk`: A reference to the decryption key.
/// - `c`: The ciphertext message as an `EncodedCiphertext<u64>`.
///
/// Returns:
/// The decrypted message as a `u64`.
fn decrypt(dk: &DecryptionKey, c: EncodedCiphertext<u64>) -> u64 {
    Paillier::decrypt(dk, c)
}
