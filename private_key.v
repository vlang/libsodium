module libsodium

pub struct Box {
	nonce      [24]byte
mut:
	key        PrivateKey
	public_key []byte
}

pub struct PrivateKey {
	nonce      [24]byte
pub:
	public_key []byte
	secret_key []byte
}

pub fn new_private_key() PrivateKey {
	mut pk := PrivateKey{
		public_key: []byte{len: public_key_size}
		secret_key: []byte{len: secret_key_size}
	}
	C.crypto_box_keypair(pk.public_key.data, pk.secret_key.data)
	return pk
}

pub fn new_box(private_key PrivateKey, public_key []byte) Box {
	box := Box{
		key: private_key
		public_key: public_key
	}
	return box
}

pub fn (box Box) encrypt_string(s string) []byte {
	buf := []byte{len: mac_size + s.len}
	res := C.crypto_box_easy(buf.data, s.str, s.len, box.nonce, box.public_key.data, box.key.secret_key.data)
	if res != 0 {
		// TODO handle errors
	}
	return buf
}

pub fn (box Box) encrypt(b []byte) []byte {
	buf := []byte{len: mac_size + b.len}
	res := C.crypto_box_easy(buf.data, b.data, b.len, box.nonce, box.public_key.data,
		box.key.secret_key.data)
	if res != 0 {
		// TODO handle errors
	}
	return buf
}

pub fn (box Box) decrypt(b []byte) []byte {
	len := b.len - mac_size
	decrypted := []byte{len: len}
	C.crypto_box_open_easy(decrypted.data, b.data, b.len, box.nonce, box.public_key.data,
		box.key.secret_key.data)
	return decrypted
}

pub fn (box Box) decrypt_string(b []byte) string {
	len := b.len - mac_size
	decrypted := []byte{len: len}
	C.crypto_box_open_easy(decrypted.data, b.data, b.len, box.nonce, box.public_key.data,
		box.key.secret_key.data)
	return string(decrypted)
}
