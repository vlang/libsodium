import libsodium
import time
import strings

fn randombytes() {
	// Random numbers generation
	println(libsodium.randombytes_random())
}

fn encr_pub_key() {
	// Public-key cryptography
	key_alice := libsodium.new_private_key()
	key_bob := libsodium.new_private_key()
	bob_box := libsodium.new_box(key_bob, key_alice.public_key)
	encrypted := bob_box.encrypt_string('hello')
	alice_box := libsodium.new_box(key_alice, key_bob.public_key)
	decrypted := alice_box.decrypt_string(encrypted)
	println(decrypted)
}

fn encr_std() {
	// Secret-key cryptography
	box := libsodium.new_secret_box('key')
	encrypted := box.encrypt_string('hello')
	decrypted := box.decrypt_string(encrypted)
	assert decrypted == 'hello'
	println(decrypted)
	encrypted_bytes := box.encrypt([byte(0), 1, 2, 3])
	decrypted_bytes := box.decrypt(encrypted_bytes)
	assert decrypted_bytes == [byte(0), 1, 2, 3]
	assert decrypted == 'hello'
}

fn perftest() {
	// stopWatch
	box := libsodium.new_secret_box('key')
	cat := 'symmetric encryption'
	nr := 1000000
	mut sw := time.new_stopwatch({})
	sw.start()
	for _ in 0 .. nr {
		encrypted := box.encrypt_string('hello')
		box.decrypt_string(encrypted)
	}
	sw.stop()
	time_ms := sw.elapsed().milliseconds()
	println('nr of ms for ${nr / 1000000}million iterations: $time_ms for test $cat')
	nr_iterations_per_msec := nr / time_ms * 1000
	println('nr iterations per sec for $cat: $nr_iterations_per_msec')
}

fn perftest2() {
	// stopWatch
	key_alice := libsodium.new_private_key()
	key_bob := libsodium.new_private_key()
	data := strings.repeat_string('a', 10 * 1024) // 10kb
	cat := 'asymm encryption'
	nr := 10000
	mut sw := time.new_stopwatch({})
	sw.start()
	for _ in 0 .. nr {
		bob_box := libsodium.new_box(key_bob, key_alice.public_key)
		alice_box := libsodium.new_box(key_alice, key_bob.public_key)
		encrypted := bob_box.encrypt_string(data)
		alice_box.decrypt_string(encrypted)
	}
	sw.stop()
	time_ms := sw.elapsed().milliseconds()
	println('nr of ms for ${nr / 1000}thousand iterations: $time_ms for test $cat')
	nr_iterations_per_msec := nr / time_ms * 1000
	println('nr iterations per sec for $cat: $nr_iterations_per_msec')
}

fn main() {
	randombytes()
	encr_pub_key()
	encr_std()
	perftest()
	perftest2()
}
