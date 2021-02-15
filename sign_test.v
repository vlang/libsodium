module libsodium

fn test_sign_string() {
	signing_key := generate_signing_key()
	x := signing_key.sign_string('hello')
	println(x)
	assert signing_key.verify_key.verify_string(x) == true
}
