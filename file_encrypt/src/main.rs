use aes::Aes128;
use base64::encode;
use ctr::cipher::{NewCipher, StreamCipher};
use generic_array::GenericArray;
use rand::rngs::OsRng;
use rand::RngCore;
use std::env;
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

fn main() {
    let args: Vec<String> = env::args().collect();
    if &args[1] == "generate" {
        generate_key();
    } else if &args[1] == "--encrypt" || &args[1] == "-e" {
        let vals = retrive_key();
        let key_bytes = base64::decode(&vals.0).expect("Invalid base64 key");
        let nonce_bytes = base64::decode(&vals.1).expect("Invalid base64 nonce");
        let key = GenericArray::from_slice(&key_bytes);
        let nonce = GenericArray::from_slice(&nonce_bytes);
        let mut cipher = ctr::Ctr128BE::<Aes128>::new(&key, &nonce);
        encrypt(cipher, &args[2]);
    } else if &args[1] == "--decrypt" || &args[1] == "-d" {
        // let vals = retrive_key();
        // let key_bytes = base64::decode(&vals.0).expect("Invalid base64 key");
        // let nonce_bytes = base64::decode(&vals.1).expect("Invalid base64 nonce");
        // let key = GenericArray::from_slice(&key_bytes);
        // let nonce = GenericArray::from_slice(&nonce_bytes);
        // let mut cipher = ctr::Ctr128BE::<Aes128>::new(&key, &nonce);
        // decrypt(cipher, &args[2]);
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

    fs::write("src/key.txt", encode(&key)).expect("Unable to write key");
    fs::write("src/nonce.txt", encode(&nonce)).expect("Unable to write nonce");
}

fn retrive_key() -> (String, String) {
    let mut key_file = File::open("src/key.txt").expect("File not found");
    let mut key = String::new();
    key_file
        .read_to_string(&mut key)
        .expect("Could not read file");
    let mut nonce_file = File::open("src/nonce.txt").expect("File not found");
    let mut nonce = String::new();
    nonce_file
        .read_to_string(&mut nonce)
        .expect("Could not read file");
    (key, nonce)
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

fn encrypt<C: StreamCipher>(mut cipher: C, file_name: &str) {
    let path = Path::new(file_name);
    let mut file = File::open(file_name).expect("File not found");
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .expect("Could not read file");
    let mut encrypted = vec![0u8; contents.len()];
    cipher.apply_keystream(&mut encrypted);
    fs::write(path, encrypted).expect("Unable to write file");
    println!("File encrypted successfully");
}
