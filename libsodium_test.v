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
	enc2 := box.encrypt_string('123456')
	dec2 := box.decrypt_string(enc2)
	assert dec2 == '123456'
	//
	enc3 := box.encrypt([byte(0), 1, 2, 3])
	dec3 := box.decrypt(enc3)
	assert dec3 == [byte(0), 1, 2, 3]
}
