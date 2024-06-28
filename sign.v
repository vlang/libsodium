module libsodium

const sign_len = 64

pub struct SigningKey {
	secret_key [secret_key_size]u8
pub:
	verify_key VerifyKey
}

pub struct VerifyKey {
pub:
	public_key [public_key_size]u8
}

pub fn new_signing_key(public_key [public_key_size]u8, secret_key [secret_key_size]u8) SigningKey {
	res := SigningKey{}
	unsafe {
		C.memcpy(&res.verify_key.public_key[0], &public_key[0], public_key.len)
		C.memcpy(&res.secret_key[0], &secret_key[0], secret_key.len)
	}
	return res
}

pub fn generate_ed25519_signing_key() SigningKey {
	mut pk := SigningKey{
		secret_key: [secret_key_size]u8{}
		verify_key: VerifyKey{
			public_key: [public_key_size]u8{}
		}
	}

	x := crypto_sign_ed25519_keypair(pk.verify_key.public_key[0], pk.secret_key[0])

	if x != 0 {
		// TODO handle errors
	}
	return pk
}

pub fn generate_signing_key() SigningKey {
	res := SigningKey{}
	C.crypto_sign_keypair(&res.verify_key.public_key[0], &res.secret_key[0])
	return res
}

pub fn new_ed25519_signing_key_seed(seed []u8) SigningKey {
	mut pk := SigningKey{
		secret_key: [secret_key_size]u8{}
		verify_key: VerifyKey{
			public_key: [public_key_size]u8{}
		}
	}

	x := crypto_sign_ed25519_seed_keypair(pk.verify_key.public_key[0], pk.secret_key[0],
		seed.data)

	if x != 0 {
		// TODO handle errors
	}
	return pk
}

pub fn new_signing_key_seed(seed []u8) SigningKey {
	res := SigningKey{}
	C.crypto_sign_seed_keypair(&res.verify_key.public_key[0], &res.secret_key[0], seed.data)
	return res
}

pub fn (key VerifyKey) verify_string(s string) bool {
	len := s.len - libsodium.sign_len
	buf := []u8{len: len}
	mut buf_len := u64(0)
	if C.crypto_sign_open(buf.data, C.ULLCAST(&buf_len), s.str, s.len, &key.public_key[0]) != 0 {
		return false
	}
	return true
}

pub fn (key SigningKey) sign_string(s string) string {
	buf_size := libsodium.sign_len + s.len
	mut buf := unsafe { vcalloc(buf_size) }
	mut buf_len := u64(0)
	C.crypto_sign(buf, C.ULLCAST(&buf_len), s.str, s.len, &key.secret_key[0])
	return unsafe { buf.vstring_with_len(int(buf_len)) }
}

pub fn (key VerifyKey) verify(b []u8) bool {
	len := b.len - libsodium.sign_len
	buf := []u8{len: len}
	mut buf_len := u64(0)
	if C.crypto_sign_open(buf.data, C.ULLCAST(&buf_len), b.data, b.len, &key.public_key[0]) != 0 {
		return false
	}
	return true
}

pub fn (key SigningKey) sign(b []u8) []u8 {
	buf := []u8{len: libsodium.sign_len + b.len}
	mut buf_len := u64(0)
	C.crypto_sign(buf.data, C.ULLCAST(&buf_len), b.data, b.len, &key.secret_key[0])
	return buf
}
