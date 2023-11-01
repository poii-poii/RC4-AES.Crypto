extern crate clap;
extern crate aes;
use clap::{App, Arg};
use std::fs::File;
use std::io::{Read, Write};
use aes::Aes128;
use aes::cipher::{
    BlockCipher, BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::GenericArray,
};

fn key_setup(key: &[u8], s_box: &mut [u8; 256]) {
    for i in 0..256 {
        s_box[i] = i as u8;
    }

    let key_len = key.len();
    let mut j = 0;
    for i in 0..256 {
        j = ((j as usize + s_box[i] as usize + key[i % key_len] as usize) % 256) as u8;
        s_box.swap(i as usize, j as usize);
    }
}

fn stream_generation(data: &mut [u8], s_box: &mut [u8; 256]) {
    let mut i = 0;
    let mut j = 0;
    let data_len = data.len();

    for index in 0..data_len {
        i = ((i as usize + 1) % 256) as u8;
        j = ((j as usize + s_box[i as usize] as usize) % 256) as u8;
        s_box.swap(i as usize, j as usize);

        let t = ((s_box[i as usize] as usize + s_box[j as usize] as usize) % 256) as u8;
        let k = s_box[t as usize];

        data[index] ^= k;
    }
}

fn aes_encrypt(data: &mut Vec<u8>, key: &[u8]) {
    // Ensure the key length is correct for AES-128 (16 bytes)
    if key.len() != 16 {
        eprintln!("AES key must be 16 bytes long.");
        std::process::exit(1);
    }

    let aes_key = GenericArray::from_slice(key);
    let cipher = Aes128::new(&aes_key);

    for chunk in data.chunks_mut(16) {
        let mut block = GenericArray::from_exact_iter(chunk.iter()).unwrap();
        cipher.encrypt_block(&mut block);
        chunk.copy_from_slice(block.as_slice());
    }
}

fn main() {
    let matches = App::new("Encryption/Decryption")
        .version("2.0")
        .author("Your Name")
        .about("Encrypts or decrypts a file using different ciphers and modes")
        .arg(
            Arg::with_name("input")
                .short("i")
                .long("input")
                .value_name("INPUT")
                .help("Input file to encrypt/decrypt")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("key")
                .short("k")
                .long("key")
                .value_name("KEY")
                .help("File containing the encryption/decryption key")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("output")
                .short("o")
                .long("output")
                .value_name("OUTPUT")
                .help("Target file for encrypted/decrypted output")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("skipbyte")
                .short("s")
                .long("skipbyte")
                .value_name("SKIPBYTE")
                .help("Number of bytes to skip at the beginning of the file")
                .takes_value(true)
                .required(false)
                .default_value("0"),
        )
        .arg(
            Arg::with_name("cipher")
                .short("c")
                .long("cipher")
                .value_name("CIPHER")
                .help("Cipher and mode (rc4, aes-ecb, aes-cbc, aes-ctr)")
                .takes_value(true)
                .required(true),
        )
        .get_matches();

    let input_file = matches.value_of("input").unwrap();
    let key_file = matches.value_of("key").unwrap();
    let output_file = matches.value_of("output").unwrap();
    let cipher = matches.value_of("cipher").unwrap();

    // Parse the skipbyte option
    let skip_bytes = matches.value_of("skipbyte").unwrap().parse::<usize>().unwrap();

    let mut input_data = Vec::new();
    let mut key_data = Vec::new();
    let mut output_data = Vec::new();

    // Read the input file
    match File::open(input_file) {
        Ok(mut file) => {
            file.read_to_end(&mut input_data).unwrap();
        }
        Err(_) => {
            eprintln!("Failed to open input file.");
            std::process::exit(1);
        }
    }

    // Read the key file
    match File::open(key_file) {
        Ok(mut file) => {
            file.read_to_end(&mut key_data).unwrap();
        }
        Err(_) => {
            eprintln!("Failed to open key file.");
            std::process::exit(1);
        }
    }
    // Preserve the specified number of bytes as clear (unencrypted)
    let clear_bytes = input_data[..skip_bytes].to_vec();
    input_data = input_data[skip_bytes..].to_vec();

    match cipher {
        "rc4" => {
            let mut s_box: [u8; 256] = [0; 256];
            key_setup(&key_data, &mut s_box);
            output_data = input_data.clone();
            stream_generation(&mut output_data, &mut s_box);
        }
        "aes-ecb" => {
			aes_encrypt(&mut input_data, &key_data);
        }
                _ => {
            eprintln!("Invalid cipher specified.");
            std::process::exit(1);
        }
    }

    // Combine the clear bytes with the encrypted data
    output_data = [clear_bytes, output_data].concat();

    // Write the result to the output file
    match File::create(output_file) {
        Ok(mut file) => {
            file.write_all(&output_data).unwrap();
        }
        Err(_) => {
            eprintln!("Failed to create the output file.");
            std::process::exit(1);
        }
    }

    println!("Encryption/Decryption completed successfully.");
}

