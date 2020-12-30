module libsodium

fn test_random() {
	x := randombytes_random()
	// println(x)
	assert x != 0
}

fn test_secret_box() {
	box := new_secret_box('key')
	b := box.encrypt_string('hello')
	res := box.decrypt_string(b)
	println(res)
}
