module libsodium

pub struct Box {
	nonce [24]u8
mut:
	key        PrivateKey
	public_key []u8
}

pub struct PrivateKey {
	nonce [24]u8
pub:
	public_key []u8
	secret_key []u8
}

pub fn new_private_key() PrivateKey {
	mut pk := PrivateKey{
		public_key: []u8{len: public_key_size}
		secret_key: []u8{len: secret_key_size}
	}
	x := C.crypto_box_keypair(pk.public_key.data, pk.secret_key.data)
	if x != 0 {
		// TODO handle errors
	}
	return pk
}

pub fn new_box(private_key PrivateKey, public_key []u8) Box {
	box := Box{
		key: private_key
		public_key: public_key
	}
	return box
}

pub fn (box Box) encrypt_string(s string) []u8 {
	buf := []u8{len: mac_size + s.len}
	res := C.crypto_box_easy(buf.data, s.str, s.len, &box.nonce[0], box.public_key.data,
		box.key.secret_key.data)
	if res != 0 {
		// TODO handle errors
	}
	return buf
}

pub fn (box Box) encrypt(b []u8) []u8 {
	buf := []u8{len: mac_size + b.len}
	res := C.crypto_box_easy(buf.data, b.data, b.len, &box.nonce[0], box.public_key.data,
		box.key.secret_key.data)
	if res != 0 {
		// TODO handle errors
	}
	return buf
}

pub fn (box Box) decrypt(b []u8) []u8 {
	len := b.len - mac_size
	decrypted := []u8{len: len}
	x := C.crypto_box_open_easy(decrypted.data, b.data, b.len, &box.nonce[0], box.public_key.data,
		box.key.secret_key.data)
	if x != 0 {
		// TODO handle errors
	}
	return decrypted
}

pub fn (box Box) decrypt_string(b []u8) string {
	len := b.len - mac_size
	decrypted := unsafe { vcalloc(len) }
	x := C.crypto_box_open_easy(decrypted, b.data, b.len, &box.nonce[0], box.public_key.data,
		box.key.secret_key.data)
	if x != 0 {
		// TODO handle errors
	}
	return unsafe { decrypted.vstring_with_len(len) }
}
