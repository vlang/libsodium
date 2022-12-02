module main

import libsodium
import aead.xchacha20poly1305_ietf as aeadmod

fn test_aead_xchacha20poly1305_without_additional_data_ietf_happy_path_works() {
	assert libsodium.sodium_init() >= 0

	hashed_passwd := aeadmod.hash_password("password123", .moderate)!

	in_clear_text_to_encrypt := "sdfjkldf2579023590"

	encrypted := aeadmod.encrypt_without_additional_data(hashed_passwd, in_clear_text_to_encrypt.bytes())!

	decrypted := aeadmod.decrypt_without_additional_data(hashed_passwd, encrypted)!
	assert decrypted == in_clear_text_to_encrypt.bytes()
}

fn test_aead_xchacha20poly1305_without_additional_data_ietf_verify() {
	assert libsodium.sodium_init() >= 0

	hashed_passwd := aeadmod.HashedPassword {
		salt: libsodium.SaltForArgon2id13 { salt_array:[u8(32), 49, 81, 185, 28, 171, 144, 185, 249, 150, 217, 153, 211, 255, 2, 163] },
    	hash_array: [u8(22), 83, 129, 79, 7, 98, 192, 31, 20, 103, 139, 131, 103, 151, 242, 13, 247, 49, 151, 32, 5, 237, 150, 89, 124, 143, 211, 77, 154, 172, 150, 42]
	}
	
	in_clear_text_to_encrypt := "sdfjkldf2579023590"

	nonce := aeadmod.Nonce {
        nonce_array: [u8(172), 116, 124, 193, 27, 19, 168, 184, 164, 31, 48, 58, 75, 203, 213, 45, 144, 149, 201, 114, 138, 165, 179, 1]
    }

	expected_encrypted := aeadmod.Encrypted {
    	encrypted_array: [u8(16), 38, 240, 142, 126, 206, 231, 94, 73, 66, 116, 107, 174, 189, 107, 181, 172, 78, 247, 105, 88, 189, 67, 74, 231, 87, 126, 64, 146, 30, 114, 31, 163, 200]
    	nonce: nonce
    	additional_data: []
	}

	encrypted := aeadmod.encrypt_using_password_and_nonce(hashed_passwd, in_clear_text_to_encrypt.bytes(), nonce, []u8{})!
	
	assert expected_encrypted == encrypted
}

fn test_aead_xchacha20poly1305_with_additional_data_ietf_verify() {
	assert libsodium.sodium_init() >= 0

	hashed_passwd := aeadmod.HashedPassword {
		salt: libsodium.SaltForArgon2id13 { salt_array:[u8(32), 49, 81, 185, 28, 171, 144, 185, 249, 150, 217, 153, 211, 255, 2, 163] },
    	hash_array: [u8(22), 83, 129, 79, 7, 98, 192, 31, 20, 103, 139, 131, 103, 151, 242, 13, 247, 49, 151, 32, 5, 237, 150, 89, 124, 143, 211, 77, 154, 172, 150, 42]
	}
	
	in_clear_text_to_encrypt := "sdfjkldf2579023590"

	nonce := aeadmod.Nonce {
        nonce_array: [u8(172), 116, 124, 193, 27, 19, 168, 184, 164, 31, 48, 58, 75, 203, 213, 45, 144, 149, 201, 114, 138, 165, 179, 1]
    }

	expected_encrypted := aeadmod.Encrypted {
    	encrypted_array: [u8(16), 38, 240, 142, 126, 206, 231, 94, 73, 66, 116, 107, 174, 189, 107, 181, 172, 78, 10, 24, 184, 80, 175, 219, 9, 252, 229, 91, 119, 51, 202, 67, 125, 31]
    	nonce: nonce
    	additional_data: [u8(1), 2, 3]
	}

	encrypted := aeadmod.encrypt_using_password_and_nonce(hashed_passwd, in_clear_text_to_encrypt.bytes(), nonce, [u8(1), 2, 3])!
	
	assert expected_encrypted == encrypted
}

fn test_aead_xchacha20poly1305_without_additional_data_tampering_detection_works() ! {
	assert libsodium.sodium_init() >= 0

	hashed_passwd := aeadmod.hash_password("password123", .moderate)!

	in_clear_text_to_encrypt := "sdfjkldf2579023590"

	encrypted := aeadmod.encrypt_without_additional_data(hashed_passwd, in_clear_text_to_encrypt.bytes())!

	// corrupt message
	mut tampered_encrypted_bytes := encrypted.encrypted_array.clone()
	tamper_byte_idx := tampered_encrypted_bytes.len / 2
	tampered_encrypted_bytes[tamper_byte_idx] = tampered_encrypted_bytes[tamper_byte_idx] + 1

	encrypted_tampered := aeadmod.Encrypted {
		encrypted_array:tampered_encrypted_bytes,
		nonce:encrypted.nonce
	}

	mut failed := false

	aeadmod.decrypt_without_additional_data(hashed_passwd, encrypted_tampered) or {
		failed = true
	}

	assert failed
}

fn test_aead_xchacha20poly1305_with_additional_data_ietf_happy_path_works() {
	assert libsodium.sodium_init() >= 0

	additional_data_needed_for_decription := "something".bytes()
	hashed_passwd := aeadmod.hash_password("password123", .moderate)!

	in_clear_text_to_encrypt := "sdfjkldf2579023590"

	encrypted := aeadmod.encrypt_with_additional_data(additional_data_needed_for_decription, hashed_passwd, in_clear_text_to_encrypt.bytes())!
	decrypted := aeadmod.decrypt_with_additional_data(additional_data_needed_for_decription, hashed_passwd, encrypted)!
	assert decrypted == in_clear_text_to_encrypt.bytes()
}

fn test_aead_xchacha20poly1305_with_additional_data_tampering_detection_works_for_corrupted_messages() ! {
	assert libsodium.sodium_init() >= 0

	additional_data_needed_for_decription := "something".bytes()
	hashed_passwd := aeadmod.hash_password("password123", .moderate)!

	in_clear_text_to_encrypt := "sdfjkldf2579023590"

	encrypted := aeadmod.encrypt_with_additional_data(additional_data_needed_for_decription, hashed_passwd, in_clear_text_to_encrypt.bytes())!

	// corrupt message
	mut tampered_encrypted_bytes := encrypted.encrypted_array.clone()
	tamper_byte_idx := tampered_encrypted_bytes.len / 2
	tampered_encrypted_bytes[tamper_byte_idx] = tampered_encrypted_bytes[tamper_byte_idx] + 1

	encrypted_tampered := aeadmod.Encrypted {
		encrypted_array:tampered_encrypted_bytes,
		nonce:encrypted.nonce
	}

	mut failed := false

	aeadmod.decrypt_with_additional_data(additional_data_needed_for_decription, hashed_passwd, encrypted_tampered) or {
		failed = true
	}

	assert failed
}

fn test_aead_xchacha20poly1305_with_additional_data_tampering_detection_works_for_corrupted_additional_data() ! {
	assert libsodium.sodium_init() >= 0

	hashed_passwd := aeadmod.hash_password("password123", .moderate)!

	in_clear_text_to_encrypt := "sdfjkldf2579023590"

	encrypted := aeadmod.encrypt_with_additional_data("something".bytes(), hashed_passwd, in_clear_text_to_encrypt.bytes())!

	mut failed := false

	//additional data different than one used for encryption
	aeadmod.decrypt_with_additional_data("someThing".bytes(), hashed_passwd, encrypted) or {
		failed = true
	}

	assert failed
}
