module secretbox

import libsodium
import math
import libsodium_extensions

const (
	crypto_secretbox_keybytes = libsodium.crypto_secretbox_keybytes()
	crypto_secretbox_macbytes = libsodium.crypto_secretbox_macbytes()
	crypto_box_messagebytes_max = libsodium.crypto_box_messagebytes_max()
	crypto_box_noncebytes = libsodium.crypto_box_noncebytes()
)

//https://doc.libsodium.org/secret-key_cryptography/secretbox

//Nonce is a randomly choosen number, used once. It is critical to never reuse it. Nonce is choosen from huge pool of numbers thus likehood that it is repeated is negligable.
pub struct Nonce {
	pub:
		nonce_array []u8
}

//hashing and salting is crucial. Passwords that are not hashed are not utilizing whole range of key values. Salting prevents practical dictionary attacks.
pub struct HashedPassword {
	pub:
		salt libsodium_extensions.SaltForArgon2id13
		hash_array []u8
}

pub struct Encrypted {
	pub:
		encrypted_array []u8
		nonce Nonce
}

pub fn hash_password_full(clear_text_password string, salt libsodium_extensions.SaltForArgon2id13, limit libsodium_extensions.PwHashLimit) !HashedPassword {
	key_len := crypto_secretbox_keybytes

	return HashedPassword{
		hash_array:libsodium_extensions.hash_password_argon2id13(key_len, clear_text_password, salt, limit)!,
		salt:salt
	}
}

pub fn hash_password(clear_text_password string, limit libsodium_extensions.PwHashLimit) !HashedPassword {
	salt := libsodium_extensions.build_random_salt_argon2id13()!
	return hash_password_full(clear_text_password, salt, limit)
}

fn build_nonce() !Nonce {
	nonce_size := crypto_box_noncebytes
	
	if int(nonce_size) <= 0 {
		return error("nonce_size must be positive")
	}

	nonce := []u8{len:int(nonce_size)}
	
	libsodium.randombytes_buf(nonce.data, usize(nonce.len)) //always successful
	return Nonce{nonce}
}

fn get_crypto_box_messagebytes_max_as_int() !int {
	messagebytes_max_raw := crypto_box_messagebytes_max
	if messagebytes_max_raw <= 0 {
		return error("crypto_box_messagebytes_max is negative")
	}
	
	messagebytes_max := if messagebytes_max_raw > u64(math.max_i32) {math.max_i32} else { int(messagebytes_max_raw)}
	result := int(messagebytes_max)
	
	if result <= 0 {
		return error("crypto_box_messagebytes_max as i32 must be positive")
	}

	return result
}

//encrypt_using_password_and_nonce should not be used directly to avoid mistakes. Instead use encrypt_using_password 
fn encrypt_using_password_and_nonce(hashed_password HashedPassword, data_to_encrypt []u8, nonce Nonce) !Encrypted {
	messagebytes_max := get_crypto_box_messagebytes_max_as_int()!
	
	if data_to_encrypt.len <= 0 || data_to_encrypt.len > messagebytes_max {
		return error("data_to_encrypt length is out of bounds")
	}
	
 	assert int(crypto_secretbox_macbytes) > 0
 	encrypted_len_needed_raw := u64(crypto_secretbox_macbytes)+u64(data_to_encrypt.len)
	assert encrypted_len_needed_raw > 0
	assert encrypted_len_needed_raw <= u64(math.max_i32)
	encrypted_len_needed := int(encrypted_len_needed_raw)

	encrypted := []u8{len:encrypted_len_needed}
	
	encrypt_had_error := libsodium.crypto_secretbox_easy(
		encrypted.data, 
		data_to_encrypt.data, u64(data_to_encrypt.len), 
		nonce.nonce_array.data, hashed_password.hash_array.data)
	assert encrypt_had_error == 0

	return Encrypted {encrypted_array:encrypted, nonce:nonce}
}

fn encrypt_using_password(hashed_password HashedPassword, data_to_encrypt []u8) !Encrypted {
	nonce := build_nonce()!
	return encrypt_using_password_and_nonce(hashed_password, data_to_encrypt, nonce)
}

pub fn decrypt_using_password(hash_password HashedPassword, encrypted Encrypted) ![]u8 {
	assert u64(encrypted.encrypted_array.len) > u64(crypto_secretbox_macbytes)
	decrypted_len_needed := encrypted.encrypted_array.len - int(crypto_secretbox_macbytes)

	assert decrypted_len_needed > 0
	assert decrypted_len_needed <= get_crypto_box_messagebytes_max_as_int()!

	mut decrypted := []u8{len:decrypted_len_needed}
	
	mut decrypt_had_error := libsodium.crypto_secretbox_open_easy(
		decrypted.data, 
		encrypted.encrypted_array.data, u64(encrypted.encrypted_array.len),
		encrypted.nonce.nonce_array.data, hash_password.hash_array.data)

	if decrypt_had_error != 0 {
		return error("crypto_secretbox_open_easy returned error=${decrypt_had_error}")
	}

	return decrypted	
}
