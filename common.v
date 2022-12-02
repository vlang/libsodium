module libsodium

const (
	crypto_pwhash_argon2id_saltbytes = crypto_pwhash_argon2id_saltbytes()
	crypto_pwhash_passwd_min         = crypto_pwhash_passwd_min()
	crypto_pwhash_passwd_max         = crypto_pwhash_passwd_max()
)

// modeled after https://doc.libsodium.org/password_hashing/default_phf

pub enum PwHashLimit {
	moderate
	sensitive
	interactive
}

pub struct SaltForArgon2id13 {
pub:
	salt_array []u8
}

fn build_random_salt_argon2id13() !SaltForArgon2id13 {
	if int(libsodium.crypto_pwhash_argon2id_saltbytes) <= 0 {
		return error('salt len must be positive')
	}

	salt := []u8{len: int(libsodium.crypto_pwhash_argon2id_saltbytes)}
	randombytes_buf(salt.data, usize(salt.len)) // always successful

	return SaltForArgon2id13{salt}
}

pub fn hash_password_argon2id13(key_len usize, clear_text_password string, salt SaltForArgon2id13, limit PwHashLimit) ![]u8 {
	assert salt.salt_array.len == int(libsodium.crypto_pwhash_argon2id_saltbytes)
	assert int(key_len) > 0

	result := []u8{len: int(key_len)}

	if clear_text_password.len < libsodium.crypto_pwhash_passwd_min
		|| clear_text_password.len > libsodium.crypto_pwhash_passwd_max {
		return error('clear_text_password length is out of bounds')
	}

	opslimit := match limit {
		.moderate { crypto_pwhash_opslimit_moderate() }
		.interactive { crypto_pwhash_opslimit_interactive() }
		.sensitive { crypto_pwhash_opslimit_sensitive() }
	}

	assert opslimit > 0

	memlimit := match limit {
		.moderate { crypto_pwhash_memlimit_moderate() }
		.interactive { crypto_pwhash_memlimit_interactive() }
		.sensitive { crypto_pwhash_memlimit_sensitive() }
	}
	assert memlimit > 0

	alg := crypto_pwhash_alg_argon2id13()

	had_error := crypto_pwhash(result.data, u64(result.len), clear_text_password.str,
		u64(clear_text_password.len), salt.salt_array.data, opslimit, memlimit, alg)

	if had_error != 0 {
		return error('crypto_pwhash failed error=${had_error}')
	}

	return result
}
