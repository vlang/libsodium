module libsodium

pub const (
	key_size   = 32 // int(C.crypto_secretbox_KEYBYTES)
	nonce_size = 24 // int(C.crypto_secretbox_NONCEBYTES)
	mac_size   = 16 //  int(C.crypto_secretbox_MACBYTES)
)

pub struct SecretBox {
	key   [32]byte
	nonce [24]byte
}

fn C.crypto_secretbox_keygen(byteptr)

pub fn new_secret_box(key string) SecretBox {
	// println('KEY SIZE=')
	// println(key_size)
	// println('MAC SIZE')
	// println(mac_size)
	box := SecretBox{}
	C.crypto_secretbox_keygen(box.key)
	C.randombytes_buf(box.nonce, nonce_size)
	/*
	buf := [21]byte{}
	res := C.crypto_secretbox_easy(buf, c'HELLO', 5, box.nonce, box.key)
	for i in 0 .. 21 {
		println(buf[i])
	}
	C.printf('res=%d sRES="%s"\n', res, buf)
	decrypted := [5]byte{}
	C.crypto_secretbox_open_easy(decrypted, buf, 21, box.nonce, box.key)
	C.printf('DEC=%s\n', decrypted)
	*/
	return box
}

pub fn (box SecretBox) encrypt_string(s string) []byte {
	buf := []byte{len: mac_size + s.len}
	res := C.crypto_secretbox_easy(buf.data, s.str, s.len, box.nonce, box.key)
	return buf
}

pub fn (box SecretBox) encrypt(b []byte) []byte {
	buf := []byte{len: mac_size + b.len}
	res := C.crypto_secretbox_easy(buf.data, b.data, b.len, box.nonce, box.key)
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
