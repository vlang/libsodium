module main

import secretbox as sb
import libsodium

fn test_crypto_pwhash_is_not_an_empty_operation() {
	assert libsodium.sodium_init() >= 0

	in_clear_text_passwd := "password123"
	hashed := sb.hash_password(in_clear_text_passwd, .moderate)! 
		
	assert in_clear_text_passwd.bytes().hex() != hashed.hash_array.hex()
}

fn test_crypto_pwhash_verify() {
	assert libsodium.sodium_init() >= 0

	in_clear_text_passwd := "password123"

	salt := libsodium.SaltForArgon2id13{[ u8(110), 131, 121, 20, 151, 201, 189, 39, 109, 5, 8, 245, 109, 92, 50, 100]}
	hashed := sb.hash_password_full(in_clear_text_passwd, salt, .moderate)! 	
	expected_hash := [u8(231), 217, 242, 140, 112, 55, 255, 165, 151, 43, 209, 26, 82, 157, 179, 8, 123, 37, 55, 136, 32, 167, 206, 56, 249, 243, 116, 94, 36, 142, 94, 148]	
 	assert expected_hash == hashed.hash_array
}

fn test_authenticated_encryption_aka_secretbox_verify() ! {
	assert libsodium.sodium_init() >= 0

	to_be_encrypted := "12345678901234567890abcdefghijklmn"
	hashed_password := sb.HashedPassword {
		salt: libsodium.SaltForArgon2id13{ 
			salt_array:[u8(159), 144, 43, 172, 175, 238, 204, 169, 84, 188, 123, 10, 50, 139, 21, 151] },
    	hash_array: [u8(87), 229, 87, 254, 224, 20, 76, 218, 20, 190, 43, 139, 111, 109, 170, 216, 27, 209, 54, 223, 200, 219, 157, 213, 193, 92, 22, 120, 69, 103, 39, 151]
	}
	nonce := sb.Nonce{
		[u8(203), 161, 162, 210, 206, 19, 198, 120, 161, 236, 59, 137, 109, 102, 4, 178, 179, 11, 190, 102, 86, 117, 116, 246]}

	encrypted := sb.encrypt_using_password_and_nonce(hashed_password, to_be_encrypted.bytes(), nonce)!

	expected_encrypted := sb.Encrypted {
    	encrypted_array: [u8(116), 164, 9, 197, 48, 22, 224, 233, 81, 33, 152, 211, 84, 165, 217, 23, 206, 116, 114, 178, 246, 143, 189, 188, 125, 115, 213, 102, 42, 24, 81, 16, 247, 153, 238, 243, 153, 191, 90, 129, 35, 110, 128, 172, 13, 17, 226, 205, 71, 227]
    	nonce: nonce
	}

	assert expected_encrypted == encrypted
}

fn test_authenticated_encryption_aka_secretbox_happy_path_works() ! {
	assert libsodium.sodium_init() >= 0

	//https://doc.libsodium.org/secret-key_cryptography/secretbox
	to_be_encrypted := r'x'
	password_for_encdec := "password123"
	hashed_password := sb.hash_password(password_for_encdec, .interactive)!
	encrypted := sb.encrypt_using_password(hashed_password, to_be_encrypted.bytes())!
	decrypted := sb.decrypt_using_password(hashed_password, encrypted)!
	assert to_be_encrypted == decrypted.bytestr()
}

fn test_authenticated_encryption_aka_secretbox_tampering_detection_works() ! {
	assert libsodium.sodium_init() >= 0

	//https://doc.libsodium.org/secret-key_cryptography/secretbox
	to_be_encrypted := r'¥ .	€/$ąęŹŻŁПЖДäüöß'
	password_for_encdec := "password123"
	hashed_password := sb.hash_password(password_for_encdec, .interactive)!
	encrypted := sb.encrypt_using_password(hashed_password, to_be_encrypted.bytes())!

	// corrupt message
	mut tampered_encrypted_bytes := encrypted.encrypted_array.clone()
	tamper_byte_idx := tampered_encrypted_bytes.len / 2
	tampered_encrypted_bytes[tamper_byte_idx] = tampered_encrypted_bytes[tamper_byte_idx] + 1

	encrypted_tampered := sb.Encrypted {
		encrypted_array:tampered_encrypted_bytes,
		nonce:encrypted.nonce
	}
	
	mut failed := false
	sb.decrypt_using_password(hashed_password, encrypted_tampered) or {
		failed = true
	}

	assert failed
}
