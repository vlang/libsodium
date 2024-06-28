module xchacha20poly1305_ietf

import libsodium
import math

const (
	crypto_aead_xchacha20poly1305_ietf_abytes           = libsodium.crypto_aead_xchacha20poly1305_ietf_abytes()
	crypto_aead_xchacha20poly1305_ietf_keybytes         = libsodium.crypto_aead_xchacha20poly1305_ietf_keybytes()
	crypto_aead_xchacha20poly1305_ietf_npubbytes        = libsodium.crypto_aead_xchacha20poly1305_ietf_npubbytes()
	crypto_aead_xchacha20poly1305_ietf_messagebytes_max = libsodium.crypto_aead_xchacha20poly1305_ietf_messagebytes_max()
)

// modeled after https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction

// Nonce is a randomly choosen number, used once. It is critical to never reuse it. Nonce is choosen from huge pool of numbers thus likehood that it is repeated is negligable.
pub struct Nonce {
pub:
	nonce_array []u8
}

// hashing and salting is crucial. Passwords that are not hashed are not utilizing whole range of key values. Salting prevents practical dictionary attacks.
pub struct HashedPassword {
pub:
	salt       libsodium.SaltForArgon2id13
	hash_array []u8
}

pub struct Encrypted {
pub:
	encrypted_array []u8
	nonce           Nonce
	additional_data []u8
}

fn build_nonce() !Nonce {
	nonce_len := xchacha20poly1305_ietf.crypto_aead_xchacha20poly1305_ietf_npubbytes
	if int(nonce_len) <= 0 {
		return error('nonce len must be positive')
	}

	nonce := []u8{len: int(nonce_len)}

	libsodium.randombytes_buf(nonce.data, u64(nonce.len)) // always successful
	return Nonce{
		nonce_array: nonce
	}
}

pub fn hash_password_full(clear_text_password string, salt libsodium.SaltForArgon2id13, limit libsodium.PwHashLimit) !HashedPassword {
	key_len := xchacha20poly1305_ietf.crypto_aead_xchacha20poly1305_ietf_keybytes

	return HashedPassword{
		hash_array: libsodium.hash_password_argon2id13(key_len, clear_text_password, salt,
			limit)!
		salt: salt
	}
}

pub fn hash_password(clear_text_password string, limit libsodium.PwHashLimit) !HashedPassword {
	salt := libsodium.build_random_salt_argon2id13()!
	return hash_password_full(clear_text_password, salt, limit)
}

fn get_crypto_box_messagebytes_max_as_int() !int {
	messagebytes_max_raw := xchacha20poly1305_ietf.crypto_aead_xchacha20poly1305_ietf_messagebytes_max

	if messagebytes_max_raw <= 0 {
		return error('crypto_aead_xchacha20poly1305_ietf_messagebytes_max is negative')
	}

	messagebytes_max := if messagebytes_max_raw > u64(max_i32) {
		int(max_i32)
	} else {
		int(messagebytes_max_raw)
	}
	result := int(messagebytes_max)

	if result <= 0 {
		return error('crypto_aead_xchacha20poly1305_ietf_messagebytes_max as i32 must be positive')
	}

	return result
}

// encrypt_using_password_and_nonce should not be used directly to avoid mistakes. Instead use encrypt_without_additional_data or encrypt
fn encrypt_using_password_and_nonce(hashed_password HashedPassword, data_to_encrypt []u8, nonce Nonce, additional_data []u8) !Encrypted {
	messagebytes_max := get_crypto_box_messagebytes_max_as_int()!

	if data_to_encrypt.len <= 0 || data_to_encrypt.len > messagebytes_max {
		return error('data_to_encrypt length is out of bounds')
	}

	assert xchacha20poly1305_ietf.crypto_aead_xchacha20poly1305_ietf_abytes > 0
	assert int(xchacha20poly1305_ietf.crypto_aead_xchacha20poly1305_ietf_abytes) > 0

	encrypted_len_raw := u64(data_to_encrypt.len) +
		u64(xchacha20poly1305_ietf.crypto_aead_xchacha20poly1305_ietf_abytes)

	assert encrypted_len_raw <= u64(max_i32)
	encrypted_len := int(encrypted_len_raw)

	mut encrypted := []u8{len: encrypted_len}

	mut fact_len := u64(0)

	mut ad := unsafe { &u8(nil) }
	mut adlen := u64(0)

	if additional_data.len > 0 {
		ad = additional_data.data

		// TODO libsodium delegates to nacl's crypto_onetimeauth_poly1305_update. not sure what the limit is
		adlen = u64(additional_data.len)
	}

	not_used := unsafe { nil }

	had_error := libsodium.crypto_aead_xchacha20poly1305_ietf_encrypt(encrypted.data,
		&fact_len, data_to_encrypt.data, u64(data_to_encrypt.len), ad, adlen, not_used,
		nonce.nonce_array.data, hashed_password.hash_array.data)

	if had_error != 0 {
		return error('crypto_aead_xchacha20poly1305_ietf_encrypt returned error=${had_error}')
	}

	assert fact_len > 0 && fact_len <= u64(encrypted_len)

	encrypted.trim(int(fact_len))

	return Encrypted{
		encrypted_array: encrypted
		nonce: nonce
		additional_data: additional_data
	}
}

pub fn decrypt_using_password_and_nonce(hashed_password HashedPassword, data_to_decrypt Encrypted, additional_data []u8) ![]u8 {
	assert data_to_decrypt.encrypted_array.len > 0

	mut decrypted := []u8{len: data_to_decrypt.encrypted_array.len}
	mut fact_len := u64(0)

	not_used := unsafe { nil }

	mut ad := unsafe { &u8(nil) }
	mut adlen := u64(0)

	if additional_data.len > 0 {
		ad = additional_data.data
		adlen = u64(additional_data.len)
	}

	had_error := libsodium.crypto_aead_xchacha20poly1305_ietf_decrypt(decrypted.data,
		&fact_len, not_used, data_to_decrypt.encrypted_array.data, u64(data_to_decrypt.encrypted_array.len),
		ad, adlen, data_to_decrypt.nonce.nonce_array.data, hashed_password.hash_array.data)

	if had_error != 0 {
		return error('crypto_aead_xchacha20poly1305_ietf_decrypt returned error=${had_error}')
	}

	assert fact_len > 0 && fact_len <= u64(data_to_decrypt.encrypted_array.len)

	decrypted.trim(int(fact_len))

	return decrypted
}

pub fn encrypt_without_additional_data(hashed_password HashedPassword, data_to_encrypt []u8) !Encrypted {
	nonce := build_nonce()!

	return encrypt_using_password_and_nonce(hashed_password, data_to_encrypt, nonce, []u8{})
}

pub fn decrypt_without_additional_data(hashed_password HashedPassword, data_to_decrypt Encrypted) ![]u8 {
	return decrypt_using_password_and_nonce(hashed_password, data_to_decrypt, []u8{})
}

pub fn encrypt_with_additional_data(additional_data []u8, hashed_password HashedPassword, data_to_encrypt []u8) !Encrypted {
	nonce := build_nonce()!

	return encrypt_using_password_and_nonce(hashed_password, data_to_encrypt, nonce, additional_data)
}

pub fn decrypt_with_additional_data(additional_data []u8, hashed_password HashedPassword, data_to_decrypt Encrypted) ![]u8 {
	return decrypt_using_password_and_nonce(hashed_password, data_to_decrypt, additional_data)
}
