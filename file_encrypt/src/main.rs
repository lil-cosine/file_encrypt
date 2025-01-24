use aes::Aes128;
use base64::encode;
use ctr::cipher::{NewCipher, StreamCipher};
use generic_array::GenericArray;
use rand::rngs::OsRng;
use rand::RngCore;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if &args[1] == "generate" {
        generate_key();
    } else if &args[1] == "--encrypt" || &args[1] == "-e" {
        // let key = GenericArray::from_slice(&key);
        // let nonce = GenericArray::from_slice(&nonce);
        // let mut cipher = ctr::Ctr128BE::<Aes128>::new(&key, &nonce);
        //encrypt(cipher);
    } else if &args[1] == "--decrypt" || &args[1] == "-d" {
        //decrypt();
    } else if &args[1] == "--help" || &args[1] == "-h" {
        help();
    } else if &args[1] == "-r" {
        println!("This is a test");
    } else {
        println!("Invalid command. Use 'help' or '-h' for help.");
    }
}

fn generate_key() {
    let mut gen = OsRng;
    let mut key: Vec<u8> = vec![0u8; 16];
    gen.fill_bytes(&mut key);
    let mut nonce: Vec<u8> = vec![0u8; 16];
    gen.fill_bytes(&mut nonce);
    println!("Key: {}", encode(&key));
    println!("Nonce: {}", encode(&nonce));
}

fn help() {
    println!("Usage: file_encrypt [OPTION] [FILE OR DIRECTORY]");
    println!("Encrypt or decrypt a file using AES-128-CTR.");
    println!();
    println!("Options:");
    println!("  -e, --encrypt    Encrypt a file");
    println!("  -d, --decrypt    Decrypt a file");
    println!("  -h, --help       Display this help message");
    println!("  -r               Recursively encrypt or decrypt a directory");
    println!("  generate         Generate a random key and nonce");
    println!("                   which are not stored anywhere");
    println!();
    println!("Examples:");
    println!("  file_encrypt -e file.txt");
    println!("  file_encrypt -d file.txt");
    println!("  file_encrypt -r -e directory");
    println!("  file_encrypt -r -d directory");
}
