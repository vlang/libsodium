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
	// Make sure different keys result in different values
	box2 := new_secret_box('key2')
	encrypted2 := box2.encrypt_string('hello')
	decrypted2 := box2.decrypt_string(encrypted2)
	assert encrypted2 != encrypted
	assert decrypted2 == 'hello'
	// Make sure the same keys result in the same values
	box3 := new_secret_box('key')
	encrypted3 := box3.encrypt_string('hello')
	decrypted3 := box3.decrypt_string(encrypted3)
	// assert encrypted3 == encrypted // TODO this should be equal?
	assert decrypted3 == 'hello'
	//
	enc2 := box.encrypt_string('123456')
	dec2 := box.decrypt_string(enc2)
	assert dec2 == '123456'
	//
	enc3 := box.encrypt([u8(0), 1, 2, 3])
	dec3 := box.decrypt(enc3)
	assert dec3 == [u8(0), 1, 2, 3]
}

fn test_private_key() {
	key_alice := new_private_key()
	key_bob := new_private_key()
	bob_box := new_box(key_bob, key_alice.public_key)
	encrypted := bob_box.encrypt_string('hello')
	alice_box := new_box(key_alice, key_bob.public_key)
	decrypted := alice_box.decrypt_string(encrypted)
	println(decrypted)
	assert decrypted == 'hello'
}
