module libsodium

fn test_random() {
	x := randombytes_random()
	// println(x)
	assert x != 0
}

fn test_secret_box() {
	box := new_secret_box('key')
	encrypted := box.encrypt_string('hello')
	decrypted := box.decrypt_string(encrypted)
	assert decrypted == 'hello'
	println(decrypted)
}
