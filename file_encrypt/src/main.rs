use aes::Aes128;
use base64::{decode, encode};
use ctr::cipher::{NewCipher, StreamCipher};
use generic_array::GenericArray;
use rand::rngs::OsRng;
use rand::RngCore;
use std::env;
use std::fs;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::path::Path;

fn main() {
    let args: Vec<String> = env::args().collect();
    if &args[1] == "generate" {
        generate_key();
    } else if args.iter().any(|arg| arg == "-r") {
        let cipher = retrive_cipher();
        if args.iter().any(|arg| arg == "-e") || args.iter().any(|arg| arg == "--encrypt") {
            let path = Path::new(&args[3]);
            if path.is_dir() {
                for entry in fs::read_dir(&args[3]).expect("Unable to read directory") {
                    let entry = entry.expect("Unable to read entry");
                    let path = entry.path();
                    let path_str = path.to_str().unwrap();
                    encrypt(cipher.clone(), path_str);
                }
            } else {
                println!("Invalid usage. Must provide a directory to encrypt.");
            }
        } else if args.iter().any(|arg| arg == "-d") || args.iter().any(|arg| arg == "--decrypt") {
            let path = Path::new(&args[3]);
            if path.is_dir() {
                for entry in fs::read_dir(&args[3]).expect("Unable to read directory") {
                    let entry = entry.expect("Unable to read entry");
                    let path = entry.path();
                    let path_str = path.to_str().unwrap();
                    decrypt(cipher.clone(), path_str);
                }
            } else {
                println!("Invalid usage. Must provide a directory to decrypt.");
            }
        }
    } else if &args[1] == "--encrypt" || &args[1] == "-e" {
        let cipher = retrive_cipher();
        for i in 2..args.len() {
            encrypt(cipher.clone(), &args[i]);
        }
    } else if &args[1] == "--decrypt" || &args[1] == "-d" {
        let cipher = retrive_cipher();
        for i in 2..args.len() {
            decrypt(cipher.clone(), &args[i]);
        }
    } else if &args[1] == "--help" || &args[1] == "-h" {
        help();
    } else {
        println!("Invalid command. Use 'help' or '-h' for help.");
    }
}

fn generate_key() {
    let key_path: &Path = Path::new("src/key.txt");
    let nonce_path: &Path = Path::new("src/nonce.txt");

    if key_path.exists() && nonce_path.exists() {
        println!("WARNING! A key and nonce already exist. Regenerating these files will cause perminant loss to all encrypted file.");
        print!("If you are sure you want to regenerate these values enter 'yes': ");
        io::stdout().flush().unwrap();

        let mut user_input = String::new();
        io::stdin()
            .read_line(&mut user_input)
            .expect("failed to read line");
        if user_input.trim() != "yes" {
            println!("Regeneration aborted");
            return;
        }
    }
    let mut gen = OsRng;
    let mut key: Vec<u8> = vec![0u8; 16];
    gen.fill_bytes(&mut key);
    let mut nonce: Vec<u8> = vec![0u8; 16];
    gen.fill_bytes(&mut nonce);

    fs::write("src/key.txt", encode(&key)).expect("Unable to write key");
    fs::write("src/nonce.txt", encode(&nonce)).expect("Unable to write nonce");
}

fn retrive_cipher() -> ctr::Ctr128BE<Aes128> {
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
    let key_bytes = base64::decode(key).expect("Invalid base64 key");
    let nonce_bytes = base64::decode(nonce).expect("Invalid base64 nonce");
    let key = GenericArray::from_slice(&key_bytes);
    let nonce = GenericArray::from_slice(&nonce_bytes);
    let cipher = ctr::Ctr128BE::<Aes128>::new(&key, &nonce);
    cipher
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
    println!("  generate         Generates a random key and nonce");
    println!("                   and stores them in txt files in the root directory");
    println!();
    println!("Examples:");
    println!("  file_encrypt -e <files>");
    println!("  file_encrypt -d <files>");
    println!("  file_encrypt -r -e <directory>");
    println!("  file_encrypt -r -d <directory>");
}

fn encrypt<C: StreamCipher>(mut cipher: C, file_name: &str) {
    let path = Path::new(file_name);
    let mut file = File::open(file_name).expect("File not found");
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)
        .expect("Could not read file");
    let mut encrypted = contents.clone();
    cipher.apply_keystream(&mut encrypted);
    fs::write(path, encode(&encrypted)).expect("Unable to write file");
    println!("File encrypted successfully");
}

fn decrypt<C: StreamCipher>(mut cipher: C, file_name: &str) {
    let path = Path::new(file_name);
    let mut file = File::open(file_name).expect("File not found");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).expect("Could not read file");
    let decoded_buffer = decode(&buffer).expect("Invalid base64");
    let mut decrypted = decoded_buffer.clone();
    cipher.apply_keystream(&mut decrypted);
    fs::write(path, decrypted).expect("Unable to write file");
    println!("File decrypted successfully");
}
