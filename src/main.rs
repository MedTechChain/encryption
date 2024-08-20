extern crate paillier;
extern crate serde_json;

use std::borrow::*;
use clap::*;
use paillier::*;
use serde_json::*;
use num_traits::*;


#[derive(Parser, Debug)]
#[command(author = None, version, about = None, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generates a new keypair and prints them
    Keygen {
        #[arg(short, long)]
        bit_length: usize,
    },
    /// Encrypts a given plaintext with the provided encryption key
    Encrypt {
        /// Plaintext to encrypt
        #[arg(short, long)]
        plaintext: String,
        /// Encryption key in JSON format
        #[arg(short, long)]
        ek: String,
    },
    /// Decrypts a given ciphertext with the provided decryption key
    Decrypt {
        /// Ciphertext to decrypt
        #[arg(short, long)]
        ciphertext: String,
        /// Decryption key in JSON format
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

            let big_int_value = BigInt::from_str_radix(plaintext, 10)
                .expect("Failed to parse the string as BigInt");
            
                let ciphertext = encrypt(&ek, RawPlaintext(Cow::Owned(big_int_value)));
            println!("{}", ciphertext.0.to_string());
        }
        Commands::Decrypt { ciphertext, dk } => {
            let dk: DecryptionKey =
                serde_json::from_str(dk).expect("Failed to deserialize DecryptionKey");
            
            let big_int_value = BigInt::from_str_radix(ciphertext, 10)
                .expect("Failed to parse the string as BigInt");
        
            let plaintext = decrypt(&dk, RawCiphertext(Cow::Owned(big_int_value)));
            println!("{}", plaintext.0.to_string());
        }
    }
}

fn generate_keys(bit_length: usize) -> (EncryptionKey, DecryptionKey) {
    let (ek, dk) = Paillier::keypair_with_modulus_size(bit_length).keys();

    (ek, dk)
}

fn encrypt<'a>(ek: &'a EncryptionKey, m: RawPlaintext<'a>) -> RawCiphertext<'a> {
    Paillier::encrypt(ek, m)
}

fn decrypt<'a>(dk: &'a DecryptionKey, c: RawCiphertext<'a>) -> RawPlaintext<'a> {
    Paillier::decrypt(dk, c)
}