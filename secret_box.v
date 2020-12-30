module libsodium

pub const (
	key_size   = 32 // int(C.crypto_secretbox_KEYBYTES)
	nonce_size = 24 // int(C.crypto_secretbox_NONCEBYTES)
	mac_size   = 16 //  int(C.crypto_secretbox_MACBYTES)
)

pub struct SecretBox {
	nonce [24]byte
mut:
	key   [32]byte
}

pub fn new_secret_box(key string) SecretBox {
	mut box := SecretBox{}
	if key == '' {
		// No key means a random one needs to be generated
		C.crypto_secretbox_keygen(box.key)
	} else {
		for i := 0; i < key_size && i < key.len; i++ {
			box.key[i] = key[i]
		}
	}
	C.randombytes_buf(box.nonce, nonce_size)
	return box
}

pub fn (box SecretBox) encrypt_string(s string) []byte {
	buf := []byte{len: mac_size + s.len}
	res := C.crypto_secretbox_easy(buf.data, s.str, s.len, box.nonce, box.key)
	if res != 0 {
		// TODO handle errors
	}
	return buf
}

pub fn (box SecretBox) encrypt(b []byte) []byte {
	buf := []byte{len: mac_size + b.len}
	res := C.crypto_secretbox_easy(buf.data, b.data, b.len, box.nonce, box.key)
	if res != 0 {
		// TODO handle errors
	}
	return buf
}

pub fn (box SecretBox) decrypt(b []byte) []byte {
	len := b.len - mac_size
	decrypted := []byte{len: len}
	C.crypto_secretbox_open_easy(decrypted.data, b.data, b.len, box.nonce, box.key)
	return decrypted
}

pub fn (box SecretBox) decrypt_string(b []byte) string {
	len := b.len - mac_size
	decrypted := []byte{len: len}
	C.crypto_secretbox_open_easy(decrypted.data, b.data, b.len, box.nonce, box.key)
	return string(decrypted)
}
