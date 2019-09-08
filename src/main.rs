extern crate ring;
use ring::{digest, pbkdf2};
static PBKDF2_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA1;

extern crate clap;
use clap::{Arg, App};

extern crate openssl;
extern crate crypto;
use crypto::{ symmetriccipher, buffer, aes, blockmodes };
use crypto::buffer::{ ReadBuffer, WriteBuffer, BufferResult };

use std::fs::File;
use std::path::Path;
use std::io;
use std::io::{prelude::*, BufReader};

use inflate::inflate_bytes;
use std::str::from_utf8;

// based off of https://gist.github.com/roblabla/4a43d0a5fc3769c815ab
// this is a hackjob that took a couple hours
// related projects:
// - 	https://github.com/roblabla/DashlaneJS/blob/master/dashlane.js#L7-L52
// - 	https://github.com/masterzen/dashlane-cli/blob/master/dashlane/vault.go#L70-L93

// first rust program so i have no idea what i'm doing
fn main() {

    let matches = App::new("Dashlane Secure Export Demystifier")
    	.version("1.0.0")
    	.about("Decrypts a given dashlane secure export")
    	.arg(Arg::with_name("file")
    		.long("file").short("f").value_name("FILE")
    		.help("The target file to decrypt")
    		.required(true))
    	.arg(Arg::with_name("password")
    		.long("password").short("p").value_name("PASSWORD")
    		.help("The password to use when decrypting")
    		.required(true))
    	.arg(Arg::with_name("output")
    		.long("output").short("o").value_name("OUTPUT")
    		.help("The output file to write the decrypted dashlane XML to")
    		.required(true))
    	.get_matches();
    
    // read command line args
    let input_file_path = matches.value_of("file").unwrap();
    let password_str = matches.value_of("password").unwrap();
    let output_file_name = matches.value_of("output").unwrap();
    let password = password_str.as_bytes();
    
    println!("password: {}", password_str);
    
    // open file
    println!("Opening file '{}'", input_file_path);
    
    let file_path = Path::new(&input_file_path);
    
    let file = match File::open(&file_path) {
    	Err(why) => panic!("Couldn't open {}: {}", file_path.display(), why.to_string()),
    	Ok(file) => file,
    };
    
    // read in the line right after -- Data BEGIN --
    let reader = BufReader::new(file);
    let mut is_data = false;
    let mut line_data = String::new();
    
    for line in reader.lines() {
    	let unwrapped_data = line.unwrap();
    
    	if is_data {
    		line_data = unwrapped_data.clone();
    		is_data = false;
    	}
   		
    	if unwrapped_data == "--------------------       Data BEGIN        ----------------------" {
    		is_data = true;
    	}
   	}
   	
   	// base64 decode the text
   	let base64_decoded = base64::decode(&line_data).unwrap();
   	let salt = &base64_decoded[0..32];
   	let compressed_bytes = &base64_decoded[32..36];
   	let mut aes: &[u8] = &[];
   	let mut is_compressed = false;
   	
   	// check for KWC3
   	if compressed_bytes == [75, 87, 67, 51] {
   		println!("KWC3 detected - this is a compressed dashlane archive.");
   		is_compressed = true;
   		aes = &base64_decoded[36..];
   	} else {
   		println!("KWC3 not detected - this is an uncompressed dashlane archive.");
   		
   		aes = &base64_decoded[32..];
   	}
   	
   	// derive a pbkdf2 key
   	
   	let mut pbkdf2_key = [0u8; 32];
   	pbkdf2::derive(
   		PBKDF2_ALG,
   		std::num::NonZeroU32::new(10204).unwrap(),
   		&salt,
   		password,
   		&mut pbkdf2_key,
   	);
   	
   	println!("pbkdf2 key: {:?}", pbkdf2_key);
   	
   	// derive OpenSSL's EVP_BytesToKey key
   	
   	let mut openssl_key: Vec<u8> = vec![]; // ?
   	let mut openssl_iv: Vec<u8> = vec![]; // ?
   	
   	match openssl::pkcs5::bytes_to_key(
   		
   		// no idea if this is the right one
   		openssl::symm::Cipher::aes_256_cbc(),
   			
   		// the notes said 'sha'
   		openssl::hash::MessageDigest::sha1(),
   			
   		&pbkdf2_key, // data
   		Some(&salt[0..8]), // salt
   			
   		1i32, // count
   	) {
   		Ok(key_iv_pair) => {
   			openssl_key = key_iv_pair.key;
   			openssl_iv = key_iv_pair.iv.unwrap();
   		},
   		Err(err) => panic!("Error running EVP_BytesToKey: {}", err),
   	}
   	
   	println!("openssl key: {:?}", openssl_key);
   	println!("openssl iv: {:?}", openssl_iv);
   	
   	if is_compressed {
   		
   		println!("decrypting aes data");
   		
    	let mut final_result_wrapped = decrypt(&aes, &pbkdf2_key, &openssl_iv);
    	
    	match final_result_wrapped {
    		Err(err) => {
    			panic!("{:?}", err);
    		},
    		Ok(_) => { },
    	};
    	
    	let mut final_result = final_result_wrapped.unwrap();
    
    	
    	println!("decoding");
    	let decoded_data = inflate_bytes(&final_result[6..]).unwrap();
		println!("decoded.");
    	
		println!("writing result");
    	let mut dashlane_file = File::create(output_file_name).unwrap();
    	dashlane_file.write_all(&decoded_data);
    	
    	println!("done!");
   	} else {
   		panic!("non compressed data isn't supported yet")
   	}
}

// Decrypts a buffer with the given key and iv using
// AES-256/CBC/Pkcs encryption.
//
// This function is very similar to encrypt(), so, please reference
// comments in that function. In non-example code, if desired, it is possible to
// share much of the implementation using closures to hide the operation
// being performed. However, such code would make this example less clear.
fn decrypt(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut decryptor = aes::cbc_decryptor(
            aes::KeySize::KeySize256,
            key,
            iv,
            blockmodes::NoPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = decryptor.decrypt(&mut read_buffer, &mut write_buffer, true)?;
        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }

    Ok(final_result)
}
