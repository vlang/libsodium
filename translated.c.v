module libsodium

#flag darwin -L/opt/homebrew/lib
#flag darwin -I/opt/homebrew/include

#include <sodium.h>
#flag -lsodium

#define UNSIGNED_LONG_LONG unsigned long long
#define ULLCAST(x) (UNSIGNED_LONG_LONG *)(x)

fn C.ULLCAST(x &u64) &C.UNSIGNED_LONG_LONG

const ( // empty enum
	blake2b_blockbytes    = 0
	blake2b_outbytes      = 1
	blake2b_keybytes      = 2
	blake2b_saltbytes     = 3
	blake2b_personalbytes = 4
)

/*
// struct decl name="blake2b_param_"
// typedef struct
// ['referenced', 'blake2b_param', 'struct blake2b_param_:struct blake2b_param_']
struct blake2b_param {
	digest_length u8
	key_length u8
	fanout u8
	depth u8
	leaf_length [4]u8
	node_offset [8]u8
	node_depth u8
	inner_length u8
	reserved [14]u8
	salt [16]u8
	personal [16]u8
}
// struct decl name="blake2b_state"
// typedef struct
// ['referenced', 'blake2b_state', 'struct blake2b_state:struct blake2b_state']
struct blake2b_state {
	h [8]u64
	t [2]u64
	f [2]u64
	buf [256]u8
	buflen size_t
	last_node u8
}
type blake2b_compress_fn = fn (&blake2b_state, & u8) int
*/

// struct decl name="blake2b_param_"
// typedef struct
// ['referenced', 'blake2b_param', 'struct blake2b_param_:struct blake2b_param_']
// struct decl name="blake2b_state"
// typedef struct
// ['referenced', 'blake2b_state', 'struct blake2b_state:struct blake2b_state']

// struct decl name="blake2b_param_"
// typedef struct
// ['referenced', 'blake2b_param', 'struct blake2b_param_:struct blake2b_param_']
// struct decl name="blake2b_state"
// typedef struct
// ['referenced', 'blake2b_state', 'struct blake2b_state:struct blake2b_state']

// struct decl name="blake2b_param_"
// typedef struct
// ['referenced', 'blake2b_param', 'struct blake2b_param_:struct blake2b_param_']
// struct decl name="blake2b_state"
// typedef struct
// ['referenced', 'blake2b_state', 'struct blake2b_state:struct blake2b_state']

// struct decl name="blake2b_param_"
// typedef struct
// ['referenced', 'blake2b_param', 'struct blake2b_param_:struct blake2b_param_']
// struct decl name="blake2b_state"
// typedef struct
// ['referenced', 'blake2b_state', 'struct blake2b_state:struct blake2b_state']
fn C.crypto_generichash_blake2b(out &u8, outlen usize, in_ &u8, inlen u64, key &u8, keylen usize) int

pub fn crypto_generichash_blake2b(out &u8, outlen usize, in_ &u8, inlen u64, key &u8, keylen usize) int {
	return C.crypto_generichash_blake2b(out, outlen, in_, inlen, key, keylen)
}

fn C.crypto_generichash_blake2b_salt_personal(out &u8, outlen usize, in_ &u8, inlen u64, key &u8, keylen usize, salt &u8, personal &u8) int

pub fn crypto_generichash_blake2b_salt_personal(out &u8, outlen usize, in_ &u8, inlen u64, key &u8, keylen usize, salt &u8, personal &u8) int {
	return C.crypto_generichash_blake2b_salt_personal(out, outlen, in_, inlen, key, keylen,
		salt, personal)
}

// struct decl name="blake2b_param_"
// typedef struct
// ['referenced', 'blake2b_param', 'struct blake2b_param_:struct blake2b_param_']
// struct decl name="blake2b_state"
// typedef struct
// ['referenced', 'blake2b_state', 'struct blake2b_state:struct blake2b_state']
fn C.crypto_generichash_primitive() &char

pub fn crypto_generichash_primitive() &char {
	return &char(C.crypto_generichash_primitive())
}

fn C.crypto_kx_publickeybytes() usize

pub fn crypto_kx_publickeybytes() usize {
	return C.crypto_kx_publickeybytes()
}

fn C.crypto_kx_secretkeybytes() usize

pub fn crypto_kx_secretkeybytes() usize {
	return C.crypto_kx_secretkeybytes()
}

fn C.crypto_kx_seedbytes() usize

pub fn crypto_kx_seedbytes() usize {
	return C.crypto_kx_seedbytes()
}

fn C.crypto_kx_sessionkeybytes() usize

pub fn crypto_kx_sessionkeybytes() usize {
	return C.crypto_kx_sessionkeybytes()
}

fn C.crypto_kx_primitive() &char

pub fn crypto_kx_primitive() &char {
	return &char(C.crypto_kx_primitive())
}

fn C.crypto_sign_primitive() &char

pub fn crypto_sign_primitive() &char {
	return &char(C.crypto_sign_primitive())
}

fn C.crypto_sign_seed_keypair(pk &u8, sk &u8, seed &u8) int

pub fn crypto_sign_seed_keypair(pk &u8, sk &u8, seed &u8) int {
	return C.crypto_sign_seed_keypair(pk, sk, seed)
}

fn C.crypto_sign_keypair(pk &u8, sk &u8) int

pub fn crypto_sign_keypair(pk &u8, sk &u8) int {
	return C.crypto_sign_keypair(pk, sk)
}

fn C.crypto_sign(sm &u8, smlen_p &C.UNSIGNED_LONG_LONG, m &u8, mlen u64, sk &u8) int

pub fn crypto_sign(sm &u8, smlen_p &u64, m &u8, mlen u64, sk &u8) int {
	return C.crypto_sign(sm, C.ULLCAST(smlen_p), m, mlen, sk)
}

fn C.crypto_sign_open(m &u8, mlen_p &C.UNSIGNED_LONG_LONG, sm &u8, smlen u64, pk &u8) int

pub fn crypto_sign_open(m &u8, mlen_p &u64, sm &u8, smlen u64, pk &u8) int {
	return C.crypto_sign_open(m, C.ULLCAST(mlen_p), sm, smlen, pk)
}

fn C.crypto_sign_detached(sig &u8, siglen_p &C.UNSIGNED_LONG_LONG, m &u8, mlen u64, sk &u8) int

pub fn crypto_sign_detached(sig &u8, siglen_p &u64, m &u8, mlen u64, sk &u8) int {
	return C.crypto_sign_detached(sig, C.ULLCAST(siglen_p), m, mlen, sk)
}

fn C.crypto_sign_verify_detached(sig &u8, m &u8, mlen u64, pk &u8) int

pub fn crypto_sign_verify_detached(sig &u8, m &u8, mlen u64, pk &u8) int {
	return C.crypto_sign_verify_detached(sig, m, mlen, pk)
}

fn C.crypto_sign_ed25519ph_statebytes() usize

pub fn crypto_sign_ed25519ph_statebytes() usize {
	return C.crypto_sign_ed25519ph_statebytes()
}

fn C.crypto_sign_ed25519_bytes() usize

pub fn crypto_sign_ed25519_bytes() usize {
	return C.crypto_sign_ed25519_bytes()
}

fn C.crypto_sign_ed25519_seedbytes() usize

pub fn crypto_sign_ed25519_seedbytes() usize {
	return C.crypto_sign_ed25519_seedbytes()
}

fn C.crypto_sign_ed25519_publickeybytes() usize

pub fn crypto_sign_ed25519_publickeybytes() usize {
	return C.crypto_sign_ed25519_publickeybytes()
}

fn C.crypto_sign_ed25519_secretkeybytes() usize

pub fn crypto_sign_ed25519_secretkeybytes() usize {
	return C.crypto_sign_ed25519_secretkeybytes()
}

fn C.crypto_sign_ed25519_messagebytes_max() usize

pub fn crypto_sign_ed25519_messagebytes_max() usize {
	return C.crypto_sign_ed25519_messagebytes_max()
}

fn C.crypto_sign_ed25519_sk_to_seed(seed &u8, sk &u8) int

pub fn crypto_sign_ed25519_sk_to_seed(seed &u8, sk &u8) int {
	return C.crypto_sign_ed25519_sk_to_seed(seed, sk)
}

fn C.crypto_sign_ed25519_sk_to_pk(pk &u8, sk &u8) int

pub fn crypto_sign_ed25519_sk_to_pk(pk &u8, sk &u8) int {
	return C.crypto_sign_ed25519_sk_to_pk(pk, sk)
}

fn C.crypto_sign_ed25519_detached(sig &u8, siglen_p &C.UNSIGNED_LONG_LONG, m &u8, mlen u64, sk &u8) int

pub fn crypto_sign_ed25519_detached(sig &u8, siglen_p &u64, m &u8, mlen u64, sk &u8) int {
	return C.crypto_sign_ed25519_detached(sig, C.ULLCAST(siglen_p), m, mlen, sk)
}

fn C.crypto_sign_ed25519(sm &u8, smlen_p &C.UNSIGNED_LONG_LONG, m &u8, mlen u64, sk &u8) int

pub fn crypto_sign_ed25519(sm &u8, smlen_p &u64, m &u8, mlen u64, sk &u8) int {
	return C.crypto_sign_ed25519(sm, C.ULLCAST(smlen_p), m, mlen, sk)
}

fn C.crypto_sign_ed25519_seed_keypair(pk &u8, sk &u8, seed &u8) int

pub fn crypto_sign_ed25519_seed_keypair(pk &u8, sk &u8, seed &u8) int {
	return C.crypto_sign_ed25519_seed_keypair(pk, sk, seed)
}

fn C.crypto_sign_ed25519_keypair(pk &u8, sk &u8) int

pub fn crypto_sign_ed25519_keypair(pk &u8, sk &u8) int {
	return C.crypto_sign_ed25519_keypair(pk, sk)
}

fn C.crypto_sign_ed25519_pk_to_curve25519(curve25519_pk &u8, ed25519_pk &u8) int

pub fn crypto_sign_ed25519_pk_to_curve25519(curve25519_pk &u8, ed25519_pk &u8) int {
	return C.crypto_sign_ed25519_pk_to_curve25519(curve25519_pk, ed25519_pk)
}

fn C.crypto_sign_ed25519_sk_to_curve25519(curve25519_sk &u8, ed25519_sk &u8) int

pub fn crypto_sign_ed25519_sk_to_curve25519(curve25519_sk &u8, ed25519_sk &u8) int {
	return C.crypto_sign_ed25519_sk_to_curve25519(curve25519_sk, ed25519_sk)
}

fn C.crypto_sign_ed25519_verify_detached(sig &u8, m &u8, mlen u64, pk &u8) int

pub fn crypto_sign_ed25519_verify_detached(sig &u8, m &u8, mlen u64, pk &u8) int {
	return C.crypto_sign_ed25519_verify_detached(sig, m, mlen, pk)
}

fn C.crypto_sign_ed25519_open(m &u8, mlen_p &C.UNSIGNED_LONG_LONG, sm &u8, smlen u64, pk &u8) int

pub fn crypto_sign_ed25519_open(m &u8, mlen_p &u64, sm &u8, smlen u64, pk &u8) int {
	return C.crypto_sign_ed25519_open(m, C.ULLCAST(mlen_p), sm, smlen, pk)
}

fn C.crypto_secretbox_xsalsa20poly1305(c &u8, m &u8, mlen u64, n &u8, k &u8) int

pub fn crypto_secretbox_xsalsa20poly1305(c &u8, m &u8, mlen u64, n &u8, k &u8) int {
	return C.crypto_secretbox_xsalsa20poly1305(c, m, mlen, n, k)
}

fn C.crypto_secretbox_macbytes() usize

pub fn crypto_secretbox_macbytes() usize {
	return C.crypto_secretbox_macbytes()
}

fn C.crypto_secretbox_xsalsa20poly1305_open(m &u8, c &u8, clen u64, n &u8, k &u8) int

pub fn crypto_secretbox_xsalsa20poly1305_open(m &u8, c &u8, clen u64, n &u8, k &u8) int {
	return C.crypto_secretbox_xsalsa20poly1305_open(m, c, clen, n, k)
}

fn C.crypto_secretbox_xchacha20poly1305_detached(c &u8, mac &u8, m &u8, mlen u64, n &u8, k &u8) int

pub fn crypto_secretbox_xchacha20poly1305_detached(c &u8, mac &u8, m &u8, mlen u64, n &u8, k &u8) int {
	return C.crypto_secretbox_xchacha20poly1305_detached(c, mac, m, mlen, n, k)
}

fn C.crypto_secretbox_xchacha20poly1305_easy(c &u8, m &u8, mlen u64, n &u8, k &u8) int

pub fn crypto_secretbox_xchacha20poly1305_easy(c &u8, m &u8, mlen u64, n &u8, k &u8) int {
	return C.crypto_secretbox_xchacha20poly1305_easy(c, m, mlen, n, k)
}

fn C.crypto_secretbox_xchacha20poly1305_open_detached(m &u8, c &u8, mac &u8, clen u64, n &u8, k &u8) int

pub fn crypto_secretbox_xchacha20poly1305_open_detached(m &u8, c &u8, mac &u8, clen u64, n &u8, k &u8) int {
	return C.crypto_secretbox_xchacha20poly1305_open_detached(m, c, mac, clen, n, k)
}

fn C.crypto_secretbox_xchacha20poly1305_open_easy(m &u8, c &u8, clen u64, n &u8, k &u8) int

pub fn crypto_secretbox_xchacha20poly1305_open_easy(m &u8, c &u8, clen u64, n &u8, k &u8) int {
	return C.crypto_secretbox_xchacha20poly1305_open_easy(m, c, clen, n, k)
}

fn C.crypto_secretbox_xchacha20poly1305_keybytes() usize

pub fn crypto_secretbox_xchacha20poly1305_keybytes() usize {
	return C.crypto_secretbox_xchacha20poly1305_keybytes()
}

fn C.crypto_box_noncebytes() usize

pub fn crypto_box_noncebytes() usize {
	return C.crypto_box_noncebytes()
}

fn C.crypto_secretbox_xchacha20poly1305_noncebytes() usize

pub fn crypto_secretbox_xchacha20poly1305_noncebytes() usize {
	return C.crypto_secretbox_xchacha20poly1305_noncebytes()
}

fn C.crypto_secretbox_xchacha20poly1305_macbytes() usize

pub fn crypto_secretbox_xchacha20poly1305_macbytes() usize {
	return C.crypto_secretbox_xchacha20poly1305_macbytes()
}

fn C.crypto_box_messagebytes_max() usize

pub fn crypto_box_messagebytes_max() usize {
	return C.crypto_box_messagebytes_max()
}

fn C.crypto_secretbox_xchacha20poly1305_messagebytes_max() usize

pub fn crypto_secretbox_xchacha20poly1305_messagebytes_max() usize {
	return C.crypto_secretbox_xchacha20poly1305_messagebytes_max()
}

fn C.crypto_secretbox_primitive() &char

pub fn crypto_secretbox_primitive() &char {
	return &char(C.crypto_secretbox_primitive())
}

fn C.crypto_secretbox(c &u8, m &u8, mlen u64, n &u8, k &u8) int

pub fn crypto_secretbox(c &u8, m &u8, mlen u64, n &u8, k &u8) int {
	return C.crypto_secretbox(c, m, mlen, n, k)
}

fn C.crypto_secretbox_open(m &u8, c &u8, clen u64, n &u8, k &u8) int

pub fn crypto_secretbox_open(m &u8, c &u8, clen u64, n &u8, k &u8) int {
	return C.crypto_secretbox_open(m, c, clen, n, k)
}

fn C.crypto_secretbox_detached(c &u8, mac &u8, m &u8, mlen u64, n &u8, k &u8) int

pub fn crypto_secretbox_detached(c &u8, mac &u8, m &u8, mlen u64, n &u8, k &u8) int {
	return C.crypto_secretbox_detached(c, mac, m, mlen, n, k)
}

fn C.crypto_secretbox_easy(c &u8, m &u8, mlen u64, n &u8, k &u8) int

pub fn crypto_secretbox_easy(c &u8, m &u8, mlen u64, n &u8, k &u8) int {
	return C.crypto_secretbox_easy(c, m, mlen, n, k)
}

fn C.crypto_secretbox_open_detached(m &u8, c &u8, mac &u8, clen u64, n &u8, k &u8) int

pub fn crypto_secretbox_open_detached(m &u8, c &u8, mac &u8, clen u64, n &u8, k &u8) int {
	return C.crypto_secretbox_open_detached(m, c, mac, clen, n, k)
}

fn C.crypto_secretbox_open_easy(m &u8, c &u8, clen u64, n &u8, k &u8) int

pub fn crypto_secretbox_open_easy(m &u8, c &u8, clen u64, n &u8, k &u8) int {
	return C.crypto_secretbox_open_easy(m, c, clen, n, k)
}

fn C.crypto_pwhash_alg_argon2i13() int

pub fn crypto_pwhash_alg_argon2i13() int {
	return C.crypto_pwhash_alg_argon2i13()
}

fn C.crypto_pwhash_alg_argon2id13() int

pub fn crypto_pwhash_alg_argon2id13() int {
	return C.crypto_pwhash_alg_argon2id13()
}

fn C.crypto_pwhash_alg_default() int

pub fn crypto_pwhash_alg_default() int {
	return C.crypto_pwhash_alg_default()
}

fn C.crypto_pwhash_bytes_min() usize

pub fn crypto_pwhash_bytes_min() usize {
	return C.crypto_pwhash_bytes_min()
}

fn C.crypto_pwhash_bytes_max() usize

pub fn crypto_pwhash_bytes_max() usize {
	return C.crypto_pwhash_bytes_max()
}

fn C.crypto_pwhash_passwd_min() usize

pub fn crypto_pwhash_passwd_min() usize {
	return C.crypto_pwhash_passwd_min()
}

fn C.crypto_pwhash_passwd_max() usize

pub fn crypto_pwhash_passwd_max() usize {
	return C.crypto_pwhash_passwd_max()
}

fn C.crypto_pwhash_saltbytes() usize

pub fn crypto_pwhash_saltbytes() usize {
	return C.crypto_pwhash_saltbytes()
}

fn C.crypto_pwhash_strbytes() usize

pub fn crypto_pwhash_strbytes() usize {
	return C.crypto_pwhash_strbytes()
}

fn C.crypto_pwhash_strprefix() &char

pub fn crypto_pwhash_strprefix() &char {
	return &char(C.crypto_pwhash_strprefix())
}

fn C.crypto_pwhash_opslimit_min() u64

pub fn crypto_pwhash_opslimit_min() u64 {
	return C.crypto_pwhash_opslimit_min()
}

fn C.crypto_pwhash_opslimit_max() u64

pub fn crypto_pwhash_opslimit_max() u64 {
	return C.crypto_pwhash_opslimit_max()
}

fn C.crypto_pwhash_memlimit_min() usize

pub fn crypto_pwhash_memlimit_min() usize {
	return C.crypto_pwhash_memlimit_min()
}

fn C.crypto_pwhash_memlimit_max() usize

pub fn crypto_pwhash_memlimit_max() usize {
	return C.crypto_pwhash_memlimit_max()
}

fn C.crypto_pwhash_opslimit_interactive() u64

pub fn crypto_pwhash_opslimit_interactive() u64 {
	return C.crypto_pwhash_opslimit_interactive()
}

fn C.crypto_pwhash_memlimit_interactive() usize

pub fn crypto_pwhash_memlimit_interactive() usize {
	return C.crypto_pwhash_memlimit_interactive()
}

fn C.crypto_pwhash_opslimit_moderate() u64

pub fn crypto_pwhash_opslimit_moderate() u64 {
	return C.crypto_pwhash_opslimit_moderate()
}

fn C.crypto_pwhash_memlimit_moderate() usize

pub fn crypto_pwhash_memlimit_moderate() usize {
	return C.crypto_pwhash_memlimit_moderate()
}

fn C.crypto_pwhash_opslimit_sensitive() u64

pub fn crypto_pwhash_opslimit_sensitive() u64 {
	return C.crypto_pwhash_opslimit_sensitive()
}

fn C.crypto_pwhash_memlimit_sensitive() usize

pub fn crypto_pwhash_memlimit_sensitive() usize {
	return C.crypto_pwhash_memlimit_sensitive()
}

fn C.crypto_pwhash(out &u8, outlen u64, passwd &u8, passwdlen u64, salt &u8, opslimit u64, memlimit usize, alg int) int

pub fn crypto_pwhash(out &u8, outlen u64, passwd &u8, passwdlen u64, salt &u8, opslimit u64, memlimit usize, alg int) int {
	return C.crypto_pwhash(out, outlen, &char(passwd), passwdlen, salt, opslimit, memlimit,
		alg)
}

fn C.crypto_pwhash_primitive() &char

pub fn crypto_pwhash_primitive() &char {
	return &char(C.crypto_pwhash_primitive())
}

enum Argon2_ErrorCodes {
	argon2_ok
	argon2_output_ptr_null
	argon2_output_too_short
	argon2_output_too_long
	argon2_pwd_too_short
	argon2_pwd_too_long
	argon2_salt_too_short
	argon2_salt_too_long
	argon2_ad_too_short
	argon2_ad_too_long
	argon2_secret_too_short
	argon2_secret_too_long
	argon2_time_too_small
	argon2_time_too_large
	argon2_memory_too_little
	argon2_memory_too_much
	argon2_lanes_too_few
	argon2_lanes_too_many
	argon2_pwd_ptr_mismatch
	argon2_salt_ptr_mismatch
	argon2_secret_ptr_mismatch
	argon2_ad_ptr_mismatch
	argon2_memory_allocation_error
	argon2_free_memory_cbk_null
	argon2_allocate_memory_cbk_null
	argon2_incorrect_parameter
	argon2_incorrect_type
	argon2_out_ptr_mismatch
	argon2_threads_too_few
	argon2_threads_too_many
	argon2_missing_args
	argon2_encoding_fail
	argon2_decoding_fail
	argon2_thread_fail
	argon2_decoding_length_fail
	argon2_verify_mismatch
}

/*
// struct decl name="Argon2_Context"
// typedef struct
// ['referenced', 'argon2_context', 'struct Argon2_Context:struct Argon2_Context']
struct argon2_context {
	out &u8
	outlen u32
	pwd &u8
	pwdlen u32
	salt &u8
	saltlen u32
	secret &u8
	secretlen u32
	ad &u8
	adlen u32
	t_cost u32
	m_cost u32
	lanes u32
	threads u32
	flags u32
}
*/
enum Argon2_type {
	argon2_i
	argon2_id
}

const ( // empty enum
	argon2_version_number        = 0
	argon2_block_size            = 1
	argon2_qwords_in_block       = 2
	argon2_owords_in_block       = 3
	argon2_hwords_in_block       = 4
	argon2_512bit_words_in_block = 5
	argon2_addresses_in_block    = 6
	argon2_prehash_digest_length = 7
	argon2_prehash_seed_length   = 8
)

// struct decl name="block_"
// typedef struct
// ['referenced', 'block', 'struct block_:struct block_']
/*
struct block {
	v [128]u64
}
// struct decl name="block_region_"
// typedef struct
// ['referenced', 'block_region', 'struct block_region_:struct block_region_']
struct block_region {
	base voidptr
	memory &block
	size size_t
}
// struct decl name="Argon2_instance_t"
// typedef struct
// ['referenced', 'argon2_instance_t', 'struct Argon2_instance_t:struct Argon2_instance_t']
struct argon2_instance_t {
	region &block_region
	pseudo_rands &u64
	passes u32
	current_pass u32
	memory_blocks u32
	segment_length u32
	lane_length u32
	lanes u32
	threads u32
	type_ Argon2_type
	print_internals int
}
// struct decl name="Argon2_position_t"
// typedef struct
// ['referenced', 'argon2_position_t', 'struct Argon2_position_t:struct Argon2_position_t']
struct argon2_position_t {
	pass u32
	lane u32
	slice byte
	index u32
}
// struct decl name="Argon2_thread_data"
// typedef struct
// ['argon2_thread_data', 'struct Argon2_thread_data:struct Argon2_thread_data']
struct argon2_thread_data {
	instance_ptr &argon2_instance_t
	pos argon2_position_t
}
type fill_segment_fn = fn (&argon2_instance_t, argon2_position_t)
*/
// struct decl name="Argon2_Context"
// typedef struct
// ['referenced', 'argon2_context', 'struct Argon2_Context:struct Argon2_Context']

// struct decl name="block_"
// typedef struct
// ['referenced', 'block', 'struct block_:struct block_']
// struct decl name="block_region_"
// typedef struct
// ['referenced', 'block_region', 'struct block_region_:struct block_region_']
// struct decl name="Argon2_instance_t"
// typedef struct
// ['referenced', 'argon2_instance_t', 'struct Argon2_instance_t:struct Argon2_instance_t']
// struct decl name="Argon2_position_t"
// typedef struct
// ['referenced', 'argon2_position_t', 'struct Argon2_position_t:struct Argon2_position_t']
// struct decl name="Argon2_thread_data"
// typedef struct
// ['argon2_thread_data', 'struct Argon2_thread_data:struct Argon2_thread_data']
// struct decl name="Argon2_Context"
// typedef struct
// ['referenced', 'argon2_context', 'struct Argon2_Context:struct Argon2_Context']

// struct decl name="block_"
// typedef struct
// ['referenced', 'block', 'struct block_:struct block_']
// struct decl name="block_region_"
// typedef struct
// ['referenced', 'block_region', 'struct block_region_:struct block_region_']
// struct decl name="Argon2_instance_t"
// typedef struct
// ['referenced', 'argon2_instance_t', 'struct Argon2_instance_t:struct Argon2_instance_t']
// struct decl name="Argon2_position_t"
// typedef struct
// ['referenced', 'argon2_position_t', 'struct Argon2_position_t:struct Argon2_position_t']
// struct decl name="Argon2_thread_data"
// typedef struct
// ['argon2_thread_data', 'struct Argon2_thread_data:struct Argon2_thread_data']
// struct decl name="Argon2_Context"
// typedef struct
// ['referenced', 'argon2_context', 'struct Argon2_Context:struct Argon2_Context']

// struct decl name="block_"
// typedef struct
// ['referenced', 'block', 'struct block_:struct block_']
// struct decl name="block_region_"
// typedef struct
// ['referenced', 'block_region', 'struct block_region_:struct block_region_']
// struct decl name="Argon2_instance_t"
// typedef struct
// ['referenced', 'argon2_instance_t', 'struct Argon2_instance_t:struct Argon2_instance_t']
// struct decl name="Argon2_position_t"
// typedef struct
// ['referenced', 'argon2_position_t', 'struct Argon2_position_t:struct Argon2_position_t']
// struct decl name="Argon2_thread_data"
// typedef struct
// ['argon2_thread_data', 'struct Argon2_thread_data:struct Argon2_thread_data']
// struct decl name="Argon2_Context"
// typedef struct
// ['referenced', 'argon2_context', 'struct Argon2_Context:struct Argon2_Context']

// struct decl name="block_"
// typedef struct
// ['referenced', 'block', 'struct block_:struct block_']
// struct decl name="block_region_"
// typedef struct
// ['referenced', 'block_region', 'struct block_region_:struct block_region_']
// struct decl name="Argon2_instance_t"
// typedef struct
// ['referenced', 'argon2_instance_t', 'struct Argon2_instance_t:struct Argon2_instance_t']
// struct decl name="Argon2_position_t"
// typedef struct
// ['referenced', 'argon2_position_t', 'struct Argon2_position_t:struct Argon2_position_t']
// struct decl name="Argon2_thread_data"
// typedef struct
// ['argon2_thread_data', 'struct Argon2_thread_data:struct Argon2_thread_data']
fn C.crypto_pwhash_argon2i_alg_argon2i13() int

pub fn crypto_pwhash_argon2i_alg_argon2i13() int {
	return C.crypto_pwhash_argon2i_alg_argon2i13()
}

fn C.crypto_pwhash_argon2i_bytes_min() usize

pub fn crypto_pwhash_argon2i_bytes_min() usize {
	return C.crypto_pwhash_argon2i_bytes_min()
}

fn C.crypto_pwhash_argon2i_bytes_max() usize

pub fn crypto_pwhash_argon2i_bytes_max() usize {
	return C.crypto_pwhash_argon2i_bytes_max()
}

fn C.crypto_pwhash_argon2i_passwd_min() usize

pub fn crypto_pwhash_argon2i_passwd_min() usize {
	return C.crypto_pwhash_argon2i_passwd_min()
}

fn C.crypto_pwhash_argon2i_passwd_max() usize

pub fn crypto_pwhash_argon2i_passwd_max() usize {
	return C.crypto_pwhash_argon2i_passwd_max()
}

fn C.crypto_pwhash_argon2i_saltbytes() usize

pub fn crypto_pwhash_argon2i_saltbytes() usize {
	return C.crypto_pwhash_argon2i_saltbytes()
}

fn C.crypto_pwhash_argon2i_strbytes() usize

pub fn crypto_pwhash_argon2i_strbytes() usize {
	return C.crypto_pwhash_argon2i_strbytes()
}

fn C.crypto_pwhash_argon2i_strprefix() &char

pub fn crypto_pwhash_argon2i_strprefix() &char {
	return &char(C.crypto_pwhash_argon2i_strprefix())
}

fn C.crypto_pwhash_argon2i_opslimit_min() u64

pub fn crypto_pwhash_argon2i_opslimit_min() u64 {
	return C.crypto_pwhash_argon2i_opslimit_min()
}

fn C.crypto_pwhash_argon2i_opslimit_max() u64

pub fn crypto_pwhash_argon2i_opslimit_max() u64 {
	return C.crypto_pwhash_argon2i_opslimit_max()
}

fn C.crypto_pwhash_argon2i_memlimit_min() usize

pub fn crypto_pwhash_argon2i_memlimit_min() usize {
	return C.crypto_pwhash_argon2i_memlimit_min()
}

fn C.crypto_pwhash_argon2i_memlimit_max() usize

pub fn crypto_pwhash_argon2i_memlimit_max() usize {
	return C.crypto_pwhash_argon2i_memlimit_max()
}

fn C.crypto_pwhash_argon2i_opslimit_interactive() u64

pub fn crypto_pwhash_argon2i_opslimit_interactive() u64 {
	return C.crypto_pwhash_argon2i_opslimit_interactive()
}

fn C.crypto_pwhash_argon2i_memlimit_interactive() usize

pub fn crypto_pwhash_argon2i_memlimit_interactive() usize {
	return C.crypto_pwhash_argon2i_memlimit_interactive()
}

fn C.crypto_pwhash_argon2i_opslimit_moderate() u64

pub fn crypto_pwhash_argon2i_opslimit_moderate() u64 {
	return C.crypto_pwhash_argon2i_opslimit_moderate()
}

fn C.crypto_pwhash_argon2i_memlimit_moderate() usize

pub fn crypto_pwhash_argon2i_memlimit_moderate() usize {
	return C.crypto_pwhash_argon2i_memlimit_moderate()
}

fn C.crypto_pwhash_argon2i_opslimit_sensitive() u64

pub fn crypto_pwhash_argon2i_opslimit_sensitive() u64 {
	return C.crypto_pwhash_argon2i_opslimit_sensitive()
}

fn C.crypto_pwhash_argon2i_memlimit_sensitive() usize

pub fn crypto_pwhash_argon2i_memlimit_sensitive() usize {
	return C.crypto_pwhash_argon2i_memlimit_sensitive()
}

fn C.crypto_pwhash_argon2i(out &u8, outlen u64, passwd &char, passwdlen u64, salt &u8, opslimit u64, memlimit usize, alg int) int

pub fn crypto_pwhash_argon2i(out &u8, outlen u64, passwd &char, passwdlen u64, salt &u8, opslimit u64, memlimit usize, alg int) int {
	return C.crypto_pwhash_argon2i(out, outlen, passwd, passwdlen, salt, opslimit, memlimit,
		alg)
}

// struct decl name="Argon2_Context"
// typedef struct
// ['referenced', 'argon2_context', 'struct Argon2_Context:struct Argon2_Context']

// struct decl name="block_"
// typedef struct
// ['referenced', 'block', 'struct block_:struct block_']
// struct decl name="block_region_"
// typedef struct
// ['referenced', 'block_region', 'struct block_region_:struct block_region_']
// struct decl name="Argon2_instance_t"
// typedef struct
// ['referenced', 'argon2_instance_t', 'struct Argon2_instance_t:struct Argon2_instance_t']
// struct decl name="Argon2_position_t"
// typedef struct
// ['referenced', 'argon2_position_t', 'struct Argon2_position_t:struct Argon2_position_t']
// struct decl name="Argon2_thread_data"
// typedef struct
// ['argon2_thread_data', 'struct Argon2_thread_data:struct Argon2_thread_data']
fn C.crypto_pwhash_argon2id_alg_argon2id13() int

pub fn crypto_pwhash_argon2id_alg_argon2id13() int {
	return C.crypto_pwhash_argon2id_alg_argon2id13()
}

fn C.crypto_pwhash_argon2id_bytes_min() usize

pub fn crypto_pwhash_argon2id_bytes_min() usize {
	return C.crypto_pwhash_argon2id_bytes_min()
}

fn C.crypto_pwhash_argon2id_bytes_max() usize

pub fn crypto_pwhash_argon2id_bytes_max() usize {
	return C.crypto_pwhash_argon2id_bytes_max()
}

fn C.crypto_pwhash_argon2id_passwd_min() usize

pub fn crypto_pwhash_argon2id_passwd_min() usize {
	return C.crypto_pwhash_argon2id_passwd_min()
}

fn C.crypto_pwhash_argon2id_passwd_max() usize

pub fn crypto_pwhash_argon2id_passwd_max() usize {
	return C.crypto_pwhash_argon2id_passwd_max()
}

fn C.crypto_pwhash_argon2id_saltbytes() usize

pub fn crypto_pwhash_argon2id_saltbytes() usize {
	return C.crypto_pwhash_argon2id_saltbytes()
}

fn C.crypto_pwhash_argon2id_strbytes() usize

pub fn crypto_pwhash_argon2id_strbytes() usize {
	return C.crypto_pwhash_argon2id_strbytes()
}

fn C.crypto_pwhash_argon2id_strprefix() &char

pub fn crypto_pwhash_argon2id_strprefix() &char {
	return &char(C.crypto_pwhash_argon2id_strprefix())
}

fn C.crypto_pwhash_argon2id_opslimit_min() u64

pub fn crypto_pwhash_argon2id_opslimit_min() u64 {
	return C.crypto_pwhash_argon2id_opslimit_min()
}

fn C.crypto_pwhash_argon2id_opslimit_max() u64

pub fn crypto_pwhash_argon2id_opslimit_max() u64 {
	return C.crypto_pwhash_argon2id_opslimit_max()
}

fn C.crypto_pwhash_argon2id_memlimit_min() usize

pub fn crypto_pwhash_argon2id_memlimit_min() usize {
	return C.crypto_pwhash_argon2id_memlimit_min()
}

fn C.crypto_pwhash_argon2id_memlimit_max() usize

pub fn crypto_pwhash_argon2id_memlimit_max() usize {
	return C.crypto_pwhash_argon2id_memlimit_max()
}

fn C.crypto_pwhash_argon2id_opslimit_interactive() u64

pub fn crypto_pwhash_argon2id_opslimit_interactive() u64 {
	return C.crypto_pwhash_argon2id_opslimit_interactive()
}

fn C.crypto_pwhash_argon2id_memlimit_interactive() usize

pub fn crypto_pwhash_argon2id_memlimit_interactive() usize {
	return C.crypto_pwhash_argon2id_memlimit_interactive()
}

fn C.crypto_pwhash_argon2id_opslimit_moderate() u64

pub fn crypto_pwhash_argon2id_opslimit_moderate() u64 {
	return C.crypto_pwhash_argon2id_opslimit_moderate()
}

fn C.crypto_pwhash_argon2id_memlimit_moderate() usize

pub fn crypto_pwhash_argon2id_memlimit_moderate() usize {
	return C.crypto_pwhash_argon2id_memlimit_moderate()
}

fn C.crypto_pwhash_argon2id_opslimit_sensitive() u64

pub fn crypto_pwhash_argon2id_opslimit_sensitive() u64 {
	return C.crypto_pwhash_argon2id_opslimit_sensitive()
}

fn C.crypto_pwhash_argon2id_memlimit_sensitive() usize

pub fn crypto_pwhash_argon2id_memlimit_sensitive() usize {
	return C.crypto_pwhash_argon2id_memlimit_sensitive()
}

fn C.crypto_pwhash_argon2id(out &u8, outlen u64, passwd &char, passwdlen u64, salt &u8, opslimit u64, memlimit usize, alg int) int

pub fn crypto_pwhash_argon2id(out &u8, outlen u64, passwd &char, passwdlen u64, salt &u8, opslimit u64, memlimit usize, alg int) int {
	return C.crypto_pwhash_argon2id(out, outlen, passwd, passwdlen, salt, opslimit, memlimit,
		alg)
}

// struct decl name="Argon2_Context"
// typedef struct
// ['referenced', 'argon2_context', 'struct Argon2_Context:struct Argon2_Context']

// struct decl name="block_"
// typedef struct
// ['referenced', 'block', 'struct block_:struct block_']
// struct decl name="block_region_"
// typedef struct
// ['referenced', 'block_region', 'struct block_region_:struct block_region_']
// struct decl name="Argon2_instance_t"
// typedef struct
// ['referenced', 'argon2_instance_t', 'struct Argon2_instance_t:struct Argon2_instance_t']
// struct decl name="Argon2_position_t"
// typedef struct
// ['referenced', 'argon2_position_t', 'struct Argon2_position_t:struct Argon2_position_t']
// struct decl name="Argon2_thread_data"
// typedef struct
// ['argon2_thread_data', 'struct Argon2_thread_data:struct Argon2_thread_data']
// struct decl name="Argon2_Context"
// typedef struct
// ['referenced', 'argon2_context', 'struct Argon2_Context:struct Argon2_Context']

// struct decl name="block_"
// typedef struct
// ['referenced', 'block', 'struct block_:struct block_']
// struct decl name="block_region_"
// typedef struct
// ['referenced', 'block_region', 'struct block_region_:struct block_region_']
// struct decl name="Argon2_instance_t"
// typedef struct
// ['referenced', 'argon2_instance_t', 'struct Argon2_instance_t:struct Argon2_instance_t']
// struct decl name="Argon2_position_t"
// typedef struct
// ['referenced', 'argon2_position_t', 'struct Argon2_position_t:struct Argon2_position_t']
// struct decl name="Argon2_thread_data"
// typedef struct
// ['argon2_thread_data', 'struct Argon2_thread_data:struct Argon2_thread_data']
// struct decl name="Argon2_Context"
// typedef struct
// ['referenced', 'argon2_context', 'struct Argon2_Context:struct Argon2_Context']

// struct decl name="block_"
// typedef struct
// ['referenced', 'block', 'struct block_:struct block_']
// struct decl name="block_region_"
// typedef struct
// ['referenced', 'block_region', 'struct block_region_:struct block_region_']
// struct decl name="Argon2_instance_t"
// typedef struct
// ['referenced', 'argon2_instance_t', 'struct Argon2_instance_t:struct Argon2_instance_t']
// struct decl name="Argon2_position_t"
// typedef struct
// ['referenced', 'argon2_position_t', 'struct Argon2_position_t:struct Argon2_position_t']
// struct decl name="Argon2_thread_data"
// typedef struct
// ['argon2_thread_data', 'struct Argon2_thread_data:struct Argon2_thread_data']
// struct decl name="struct"
// typedef struct
// ['referenced', 'escrypt_region_t', 'struct escrypt_region_t:escrypt_region_t']
/*
struct escrypt_region_t {
	base voidptr
	aligned voidptr
	size size_t
}
type escrypt_local_t = escrypt_region_t
type escrypt_kdf_t = fn (&escrypt_local_t, &u8, size_t, &u8, size_t, u64, u32, u32, &u8, size_t) int
*/
// struct decl name="struct"
// typedef struct
// ['referenced', 'escrypt_region_t', 'struct escrypt_region_t:escrypt_region_t']
fn C.crypto_pwhash_scryptsalsa208sha256_ll(passwd &u8, passwdlen usize, salt &u8, saltlen usize, N u64, r u32, p u32, buf &u8, buflen usize) int

pub fn crypto_pwhash_scryptsalsa208sha256_ll(passwd &u8, passwdlen usize, salt &u8, saltlen usize, n u64, r u32, p u32, buf &u8, buflen usize) int {
	return C.crypto_pwhash_scryptsalsa208sha256_ll(passwd, passwdlen, salt, saltlen, n,
		r, p, buf, buflen)
}

// struct decl name="struct"
// typedef struct
// ['referenced', 'escrypt_region_t', 'struct escrypt_region_t:escrypt_region_t']
// struct decl name="escrypt_block_t"
// typedef struct
// ['referenced', 'escrypt_block_t', 'union escrypt_block_t:union escrypt_block_t']
/*
struct escrypt_block_t {
	w [16]u32
	q [8]u64
}
*/
// struct decl name="struct"
// typedef struct
// ['referenced', 'escrypt_region_t', 'struct escrypt_region_t:escrypt_region_t']
fn C.crypto_pwhash_scryptsalsa208sha256_bytes_min() usize

pub fn crypto_pwhash_scryptsalsa208sha256_bytes_min() usize {
	return C.crypto_pwhash_scryptsalsa208sha256_bytes_min()
}

fn C.crypto_pwhash_scryptsalsa208sha256_bytes_max() usize

pub fn crypto_pwhash_scryptsalsa208sha256_bytes_max() usize {
	return C.crypto_pwhash_scryptsalsa208sha256_bytes_max()
}

fn C.crypto_pwhash_scryptsalsa208sha256_passwd_min() usize

pub fn crypto_pwhash_scryptsalsa208sha256_passwd_min() usize {
	return C.crypto_pwhash_scryptsalsa208sha256_passwd_min()
}

fn C.crypto_pwhash_scryptsalsa208sha256_passwd_max() usize

pub fn crypto_pwhash_scryptsalsa208sha256_passwd_max() usize {
	return C.crypto_pwhash_scryptsalsa208sha256_passwd_max()
}

fn C.crypto_pwhash_scryptsalsa208sha256_saltbytes() usize

pub fn crypto_pwhash_scryptsalsa208sha256_saltbytes() usize {
	return C.crypto_pwhash_scryptsalsa208sha256_saltbytes()
}

fn C.crypto_pwhash_scryptsalsa208sha256_strbytes() usize

pub fn crypto_pwhash_scryptsalsa208sha256_strbytes() usize {
	return C.crypto_pwhash_scryptsalsa208sha256_strbytes()
}

fn C.crypto_pwhash_scryptsalsa208sha256_strprefix() &char

pub fn crypto_pwhash_scryptsalsa208sha256_strprefix() &char {
	return &char(C.crypto_pwhash_scryptsalsa208sha256_strprefix())
}

fn C.crypto_pwhash_scryptsalsa208sha256_opslimit_min() u64

pub fn crypto_pwhash_scryptsalsa208sha256_opslimit_min() u64 {
	return C.crypto_pwhash_scryptsalsa208sha256_opslimit_min()
}

fn C.crypto_pwhash_scryptsalsa208sha256_opslimit_max() u64

pub fn crypto_pwhash_scryptsalsa208sha256_opslimit_max() u64 {
	return C.crypto_pwhash_scryptsalsa208sha256_opslimit_max()
}

fn C.crypto_pwhash_scryptsalsa208sha256_memlimit_min() usize

pub fn crypto_pwhash_scryptsalsa208sha256_memlimit_min() usize {
	return C.crypto_pwhash_scryptsalsa208sha256_memlimit_min()
}

fn C.crypto_pwhash_scryptsalsa208sha256_memlimit_max() usize

pub fn crypto_pwhash_scryptsalsa208sha256_memlimit_max() usize {
	return C.crypto_pwhash_scryptsalsa208sha256_memlimit_max()
}

fn C.crypto_pwhash_scryptsalsa208sha256_opslimit_interactive() u64

pub fn crypto_pwhash_scryptsalsa208sha256_opslimit_interactive() u64 {
	return C.crypto_pwhash_scryptsalsa208sha256_opslimit_interactive()
}

fn C.crypto_pwhash_scryptsalsa208sha256_memlimit_interactive() usize

pub fn crypto_pwhash_scryptsalsa208sha256_memlimit_interactive() usize {
	return C.crypto_pwhash_scryptsalsa208sha256_memlimit_interactive()
}

fn C.crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive() u64

pub fn crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive() u64 {
	return C.crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive()
}

fn C.crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive() usize

pub fn crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive() usize {
	return C.crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive()
}

fn C.crypto_pwhash_scryptsalsa208sha256(out &u8, outlen u64, passwd &char, passwdlen u64, salt &u8, opslimit u64, memlimit usize) int

pub fn crypto_pwhash_scryptsalsa208sha256(out &u8, outlen u64, passwd &char, passwdlen u64, salt &u8, opslimit u64, memlimit usize) int {
	return C.crypto_pwhash_scryptsalsa208sha256(out, outlen, passwd, passwdlen, salt,
		opslimit, memlimit)
}

fn C.crypto_verify_16_bytes() usize

pub fn crypto_verify_16_bytes() usize {
	return C.crypto_verify_16_bytes()
}

fn C.crypto_verify_32_bytes() usize

pub fn crypto_verify_32_bytes() usize {
	return C.crypto_verify_32_bytes()
}

fn C.crypto_verify_64_bytes() usize

pub fn crypto_verify_64_bytes() usize {
	return C.crypto_verify_64_bytes()
}

fn C.crypto_verify_16(x &u8, y &u8) int

pub fn crypto_verify_16(x &u8, y &u8) int {
	return C.crypto_verify_16(x, y)
}

fn C.crypto_verify_32(x &u8, y &u8) int

pub fn crypto_verify_32(x &u8, y &u8) int {
	return C.crypto_verify_32(x, y)
}

fn C.crypto_verify_64(x &u8, y &u8) int

pub fn crypto_verify_64(x &u8, y &u8) int {
	return C.crypto_verify_64(x, y)
}

fn C.crypto_auth_hmacsha512_bytes() usize

pub fn crypto_auth_hmacsha512_bytes() usize {
	return C.crypto_auth_hmacsha512_bytes()
}

fn C.crypto_auth_hmacsha512_keybytes() usize

pub fn crypto_auth_hmacsha512_keybytes() usize {
	return C.crypto_auth_hmacsha512_keybytes()
}

fn C.crypto_auth_hmacsha512_statebytes() usize

pub fn crypto_auth_hmacsha512_statebytes() usize {
	return C.crypto_auth_hmacsha512_statebytes()
}

fn C.crypto_auth_hmacsha512(out &u8, in_ &u8, inlen u64, k &u8) int

pub fn crypto_auth_hmacsha512(out &u8, in_ &u8, inlen u64, k &u8) int {
	return C.crypto_auth_hmacsha512(out, in_, inlen, k)
}

fn C.crypto_auth_hmacsha512_verify(h &u8, in_ &u8, inlen u64, k &u8) int

pub fn crypto_auth_hmacsha512_verify(h &u8, in_ &u8, inlen u64, k &u8) int {
	return C.crypto_auth_hmacsha512_verify(h, in_, inlen, k)
}

fn C.crypto_auth_hmacsha512256_bytes() usize

pub fn crypto_auth_hmacsha512256_bytes() usize {
	return C.crypto_auth_hmacsha512256_bytes()
}

fn C.crypto_auth_hmacsha512256_keybytes() usize

pub fn crypto_auth_hmacsha512256_keybytes() usize {
	return C.crypto_auth_hmacsha512256_keybytes()
}

fn C.crypto_auth_hmacsha512256_statebytes() usize

pub fn crypto_auth_hmacsha512256_statebytes() usize {
	return C.crypto_auth_hmacsha512256_statebytes()
}

fn C.crypto_auth_hmacsha512256(out &u8, in_ &u8, inlen u64, k &u8) int

pub fn crypto_auth_hmacsha512256(out &u8, in_ &u8, inlen u64, k &u8) int {
	return C.crypto_auth_hmacsha512256(out, in_, inlen, k)
}

fn C.crypto_auth_hmacsha512256_verify(h &u8, in_ &u8, inlen u64, k &u8) int

pub fn crypto_auth_hmacsha512256_verify(h &u8, in_ &u8, inlen u64, k &u8) int {
	return C.crypto_auth_hmacsha512256_verify(h, in_, inlen, k)
}

fn C.crypto_auth_primitive() &char

pub fn crypto_auth_primitive() &char {
	return &char(C.crypto_auth_primitive())
}

fn C.crypto_auth(out &u8, in_ &u8, inlen u64, k &u8) int

pub fn crypto_auth(out &u8, in_ &u8, inlen u64, k &u8) int {
	return C.crypto_auth(out, in_, inlen, k)
}

fn C.crypto_auth_verify(h &u8, in_ &u8, inlen u64, k &u8) int

pub fn crypto_auth_verify(h &u8, in_ &u8, inlen u64, k &u8) int {
	return C.crypto_auth_verify(h, in_, inlen, k)
}

fn C.crypto_auth_hmacsha256_bytes() usize

pub fn crypto_auth_hmacsha256_bytes() usize {
	return C.crypto_auth_hmacsha256_bytes()
}

fn C.crypto_auth_hmacsha256_keybytes() usize

pub fn crypto_auth_hmacsha256_keybytes() usize {
	return C.crypto_auth_hmacsha256_keybytes()
}

fn C.crypto_auth_hmacsha256_statebytes() usize

pub fn crypto_auth_hmacsha256_statebytes() usize {
	return C.crypto_auth_hmacsha256_statebytes()
}

fn C.crypto_auth_hmacsha256(out &u8, in_ &u8, inlen u64, k &u8) int

pub fn crypto_auth_hmacsha256(out &u8, in_ &u8, inlen u64, k &u8) int {
	return C.crypto_auth_hmacsha256(out, in_, inlen, k)
}

fn C.crypto_auth_hmacsha256_verify(h &u8, in_ &u8, inlen u64, k &u8) int

pub fn crypto_auth_hmacsha256_verify(h &u8, in_ &u8, inlen u64, k &u8) int {
	return C.crypto_auth_hmacsha256_verify(h, in_, inlen, k)
}

fn C.crypto_kdf_primitive() &char

pub fn crypto_kdf_primitive() &char {
	return &char(C.crypto_kdf_primitive())
}

fn C.crypto_shorthash_primitive() &char

pub fn crypto_shorthash_primitive() &char {
	return &char(C.crypto_shorthash_primitive())
}

fn C.crypto_shorthash(out &u8, in_ &u8, inlen u64, k &u8) int

pub fn crypto_shorthash(out &u8, in_ &u8, inlen u64, k &u8) int {
	return C.crypto_shorthash(out, in_, inlen, k)
}

fn C.crypto_shorthash_siphashx24(out &u8, in_ &u8, inlen u64, k &u8) int

pub fn crypto_shorthash_siphashx24(out &u8, in_ &u8, inlen u64, k &u8) int {
	return C.crypto_shorthash_siphashx24(out, in_, inlen, k)
}

fn C.crypto_shorthash_siphash24(out &u8, in_ &u8, inlen u64, k &u8) int

pub fn crypto_shorthash_siphash24(out &u8, in_ &u8, inlen u64, k &u8) int {
	return C.crypto_shorthash_siphash24(out, in_, inlen, k)
}

fn C.crypto_scalarmult_base(q &u8, n &u8) int

pub fn crypto_scalarmult_base(q &u8, n &u8) int {
	return C.crypto_scalarmult_base(q, n)
}

fn C.crypto_scalarmult(q &u8, n &u8, p &u8) int

pub fn crypto_scalarmult(q &u8, n &u8, p &u8) int {
	return C.crypto_scalarmult(q, n, p)
}

fn C.crypto_scalarmult_ed25519(q &u8, n &u8, p &u8) int

pub fn crypto_scalarmult_ed25519(q &u8, n &u8, p &u8) int {
	return C.crypto_scalarmult_ed25519(q, n, p)
}

fn C.crypto_scalarmult_ed25519_noclamp(q &u8, n &u8, p &u8) int

pub fn crypto_scalarmult_ed25519_noclamp(q &u8, n &u8, p &u8) int {
	return C.crypto_scalarmult_ed25519_noclamp(q, n, p)
}

fn C.crypto_scalarmult_ed25519_base(q &u8, n &u8) int

pub fn crypto_scalarmult_ed25519_base(q &u8, n &u8) int {
	return C.crypto_scalarmult_ed25519_base(q, n)
}

fn C.crypto_scalarmult_ed25519_base_noclamp(q &u8, n &u8) int

pub fn crypto_scalarmult_ed25519_base_noclamp(q &u8, n &u8) int {
	return C.crypto_scalarmult_ed25519_base_noclamp(q, n)
}

fn C.crypto_scalarmult_ed25519_bytes() usize

pub fn crypto_scalarmult_ed25519_bytes() usize {
	return C.crypto_scalarmult_ed25519_bytes()
}

fn C.crypto_scalarmult_ed25519_scalarbytes() usize

pub fn crypto_scalarmult_ed25519_scalarbytes() usize {
	return C.crypto_scalarmult_ed25519_scalarbytes()
}

// struct decl name="struct"
// typedef struct
// ['referenced', '_sodium_scalarmult_curve25519_sandy2x_fe51', 'struct _sodium_scalarmult_curve25519_sandy2x_fe51:_sodium_scalarmult_curve25519_sandy2x_fe51']
/*
struct _sodium_scalarmult_curve25519_sandy2x_fe51 {
	v [5]u64

}
// struct decl name="crypto_scalarmult_curve25519_implementation"
// typedef struct
// ['referenced', 'crypto_scalarmult_curve25519_implementation', 'struct crypto_scalarmult_curve25519_implementation:struct crypto_scalarmult_curve25519_implementation']
struct crypto_scalarmult_curve25519_implementation {
	mult fn (byteptr, byteptr, byteptr) int
	mult_base fn (byteptr, byteptr) int
}
*/
fn C.crypto_scalarmult_curve25519(q &u8, n &u8, p &u8) int

pub fn crypto_scalarmult_curve25519(q &u8, n &u8, p &u8) int {
	return C.crypto_scalarmult_curve25519(q, n, p)
}

fn C.crypto_scalarmult_curve25519_base(q &u8, n &u8) int

pub fn crypto_scalarmult_curve25519_base(q &u8, n &u8) int {
	return C.crypto_scalarmult_curve25519_base(q, n)
}

// struct decl name="crypto_scalarmult_curve25519_implementation"
// typedef struct
// ['crypto_scalarmult_curve25519_implementation', 'struct crypto_scalarmult_curve25519_implementation:struct crypto_scalarmult_curve25519_implementation']
fn C.crypto_onetimeauth(out &u8, in_ &u8, inlen u64, k &u8) int

pub fn crypto_onetimeauth(out &u8, in_ &u8, inlen u64, k &u8) int {
	return C.crypto_onetimeauth(out, in_, inlen, k)
}

fn C.crypto_onetimeauth_verify(h &u8, in_ &u8, inlen u64, k &u8) int

pub fn crypto_onetimeauth_verify(h &u8, in_ &u8, inlen u64, k &u8) int {
	return C.crypto_onetimeauth_verify(h, in_, inlen, k)
}

fn C.crypto_onetimeauth_primitive() &char

pub fn crypto_onetimeauth_primitive() &char {
	return &char(C.crypto_onetimeauth_primitive())
}

// struct decl name="crypto_onetimeauth_poly1305_implementation"
// typedef struct
// ['crypto_onetimeauth_poly1305_implementation', 'struct crypto_onetimeauth_poly1305_implementation:struct crypto_onetimeauth_poly1305_implementation']
/*
struct crypto_onetimeauth_poly1305_implementation {
	onetimeauth fn (byteptr, byteptr, u64, byteptr) int
	onetimeauth_verify fn (byteptr, byteptr, u64, byteptr) int
	onetimeauth_init fn (&int, byteptr) int
	onetimeauth_update fn (&int, byteptr, u64) int
	onetimeauth_final fn (&int, byteptr) int
}
// struct decl name="poly1305_state_internal_t"
// typedef struct
// ['referenced', 'poly1305_state_internal_t', 'struct poly1305_state_internal_t:struct poly1305_state_internal_t']
struct poly1305_state_internal_t {
	r [5]u32
	h [5]u32
	pad [4]u32
	leftover u64
	buffer [16]u8
	final u8
}
*/
// struct decl name="crypto_onetimeauth_poly1305_implementation"
// typedef struct
// ['crypto_onetimeauth_poly1305_implementation', 'struct crypto_onetimeauth_poly1305_implementation:struct crypto_onetimeauth_poly1305_implementation']
// struct decl name="crypto_onetimeauth_poly1305_implementation"
// typedef struct
// ['referenced', 'crypto_onetimeauth_poly1305_implementation', 'struct crypto_onetimeauth_poly1305_implementation:struct crypto_onetimeauth_poly1305_implementation']
fn C.crypto_onetimeauth_poly1305(out &u8, in_ &u8, inlen u64, k &u8) int

pub fn crypto_onetimeauth_poly1305(out &u8, in_ &u8, inlen u64, k &u8) int {
	return C.crypto_onetimeauth_poly1305(out, in_, inlen, k)
}

fn C.crypto_onetimeauth_poly1305_verify(h &u8, in_ &u8, inlen u64, k &u8) int

pub fn crypto_onetimeauth_poly1305_verify(h &u8, in_ &u8, inlen u64, k &u8) int {
	return C.crypto_onetimeauth_poly1305_verify(h, in_, inlen, k)
}

fn C.crypto_onetimeauth_poly1305_bytes() usize

pub fn crypto_onetimeauth_poly1305_bytes() usize {
	return C.crypto_onetimeauth_poly1305_bytes()
}

fn C.crypto_onetimeauth_poly1305_keybytes() usize

pub fn crypto_onetimeauth_poly1305_keybytes() usize {
	return C.crypto_onetimeauth_poly1305_keybytes()
}

fn C.crypto_onetimeauth_poly1305_statebytes() usize

pub fn crypto_onetimeauth_poly1305_statebytes() usize {
	return C.crypto_onetimeauth_poly1305_statebytes()
}

// struct decl name="SysRandom_"
// typedef struct
// ['referenced', 'SysRandom', 'struct SysRandom_:struct SysRandom_']
struct SysRandom {
	random_data_source_fd int
	initialized           int
	getrandom_available   int
}

// struct decl name="InternalRandomGlobal_"
// typedef struct
// ['referenced', 'InternalRandomGlobal', 'struct InternalRandomGlobal_:struct InternalRandomGlobal_']
struct InternalRandomGlobal {
	initialized           int
	random_data_source_fd int
	getentropy_available  int
	getrandom_available   int
	rdrand_available      int
}

// struct decl name="InternalRandom_"
// typedef struct
// ['referenced', 'InternalRandom', 'struct InternalRandom_:struct InternalRandom_']
struct InternalRandom {
	initialized   int
	rnd32_outleft usize
	key           u8
	rnd32         u8
	nonce         u64
}

fn C.randombytes_implementation_name() &char

pub fn randombytes_implementation_name() &char {
	return &char(C.randombytes_implementation_name())
}

fn C.randombytes_random() u32

pub fn randombytes_random() u32 {
	return C.randombytes_random()
}

fn C.randombytes_uniform(upper_bound u32) u32

pub fn randombytes_uniform(upper_bound u32) u32 {
	return C.randombytes_uniform(upper_bound)
}

fn C.randombytes_buf(buf voidptr, size usize)

pub fn randombytes_buf(buf voidptr, size usize) {
	C.randombytes_buf(buf, size)
}

fn C.randombytes_seedbytes() usize

pub fn randombytes_seedbytes() usize {
	return C.randombytes_seedbytes()
}

fn C.randombytes_close() int

pub fn randombytes_close() int {
	return C.randombytes_close()
}

fn C.randombytes(buf &u8, buf_len u64)

pub fn randombytes(buf &u8, buf_len u64) {
	C.randombytes(buf, buf_len)
}

fn C.crypto_box_detached_afternm(c &u8, mac &u8, m &u8, mlen u64, n &u8, k &u8) int

pub fn crypto_box_detached_afternm(c &u8, mac &u8, m &u8, mlen u64, n &u8, k &u8) int {
	return C.crypto_box_detached_afternm(c, mac, m, mlen, n, k)
}

fn C.crypto_box_detached(c &u8, mac &u8, m &u8, mlen u64, n &u8, pk &u8, sk &u8) int

pub fn crypto_box_detached(c &u8, mac &u8, m &u8, mlen u64, n &u8, pk &u8, sk &u8) int {
	return C.crypto_box_detached(c, mac, m, mlen, n, pk, sk)
}

fn C.crypto_box_easy_afternm(c &u8, m &u8, mlen u64, n &u8, k &u8) int

pub fn crypto_box_easy_afternm(c &u8, m &u8, mlen u64, n &u8, k &u8) int {
	return C.crypto_box_easy_afternm(c, m, mlen, n, k)
}

fn C.crypto_box_easy(c &u8, m &u8, mlen u64, n &u8, pk &u8, sk &u8) int

pub fn crypto_box_easy(c &u8, m &u8, mlen u64, n &u8, pk &u8, sk &u8) int {
	return C.crypto_box_easy(c, m, mlen, n, pk, sk)
}

fn C.crypto_box_open_detached_afternm(m &u8, c &u8, mac &u8, clen u64, n &u8, k &u8) int

pub fn crypto_box_open_detached_afternm(m &u8, c &u8, mac &u8, clen u64, n &u8, k &u8) int {
	return C.crypto_box_open_detached_afternm(m, c, mac, clen, n, k)
}

fn C.crypto_box_open_detached(m &u8, c &u8, mac &u8, clen u64, n &u8, pk &u8, sk &u8) int

pub fn crypto_box_open_detached(m &u8, c &u8, mac &u8, clen u64, n &u8, pk &u8, sk &u8) int {
	return C.crypto_box_open_detached(m, c, mac, clen, n, pk, sk)
}

fn C.crypto_box_open_easy_afternm(m &u8, c &u8, clen u64, n &u8, k &u8) int

pub fn crypto_box_open_easy_afternm(m &u8, c &u8, clen u64, n &u8, k &u8) int {
	return C.crypto_box_open_easy_afternm(m, c, clen, n, k)
}

fn C.crypto_box_open_easy(m &u8, c &u8, clen u64, n &u8, pk &u8, sk &u8) int

pub fn crypto_box_open_easy(m &u8, c &u8, clen u64, n &u8, pk &u8, sk &u8) int {
	return C.crypto_box_open_easy(m, c, clen, n, pk, sk)
}

fn C.crypto_box_seal(c &u8, m &u8, mlen u64, pk &u8) int

pub fn crypto_box_seal(c &u8, m &u8, mlen u64, pk &u8) int {
	return C.crypto_box_seal(c, m, mlen, pk)
}

fn C.crypto_box_seal_open(m &u8, c &u8, clen u64, pk &u8, sk &u8) int

pub fn crypto_box_seal_open(m &u8, c &u8, clen u64, pk &u8, sk &u8) int {
	return C.crypto_box_seal_open(m, c, clen, pk, sk)
}

fn C.crypto_box_sealbytes() usize

pub fn crypto_box_sealbytes() usize {
	return C.crypto_box_sealbytes()
}

fn C.crypto_box_curve25519xsalsa20poly1305_seed_keypair(pk &u8, sk &u8, seed &u8) int

pub fn crypto_box_curve25519xsalsa20poly1305_seed_keypair(pk &u8, sk &u8, seed &u8) int {
	return C.crypto_box_curve25519xsalsa20poly1305_seed_keypair(pk, sk, seed)
}

fn C.crypto_box_curve25519xsalsa20poly1305_keypair(pk &u8, sk &u8) int

pub fn crypto_box_curve25519xsalsa20poly1305_keypair(pk &u8, sk &u8) int {
	return C.crypto_box_curve25519xsalsa20poly1305_keypair(pk, sk)
}

fn C.crypto_box_curve25519xsalsa20poly1305_beforenm(k &u8, pk &u8, sk &u8) int

pub fn crypto_box_curve25519xsalsa20poly1305_beforenm(k &u8, pk &u8, sk &u8) int {
	return C.crypto_box_curve25519xsalsa20poly1305_beforenm(k, pk, sk)
}

fn C.crypto_box_curve25519xsalsa20poly1305_afternm(c &u8, m &u8, mlen u64, n &u8, k &u8) int

pub fn crypto_box_curve25519xsalsa20poly1305_afternm(c &u8, m &u8, mlen u64, n &u8, k &u8) int {
	return C.crypto_box_curve25519xsalsa20poly1305_afternm(c, m, mlen, n, k)
}

fn C.crypto_box_curve25519xsalsa20poly1305_open_afternm(m &u8, c &u8, clen u64, n &u8, k &u8) int

pub fn crypto_box_curve25519xsalsa20poly1305_open_afternm(m &u8, c &u8, clen u64, n &u8, k &u8) int {
	return C.crypto_box_curve25519xsalsa20poly1305_open_afternm(m, c, clen, n, k)
}

fn C.crypto_box_curve25519xsalsa20poly1305(c &u8, m &u8, mlen u64, n &u8, pk &u8, sk &u8) int

pub fn crypto_box_curve25519xsalsa20poly1305(c &u8, m &u8, mlen u64, n &u8, pk &u8, sk &u8) int {
	return C.crypto_box_curve25519xsalsa20poly1305(c, m, mlen, n, pk, sk)
}

fn C.crypto_box_curve25519xsalsa20poly1305_open(m &u8, c &u8, clen u64, n &u8, pk &u8, sk &u8) int

pub fn crypto_box_curve25519xsalsa20poly1305_open(m &u8, c &u8, clen u64, n &u8, pk &u8, sk &u8) int {
	return C.crypto_box_curve25519xsalsa20poly1305_open(m, c, clen, n, pk, sk)
}

fn C.crypto_box_curve25519xsalsa20poly1305_seedbytes() usize

pub fn crypto_box_curve25519xsalsa20poly1305_seedbytes() usize {
	return C.crypto_box_curve25519xsalsa20poly1305_seedbytes()
}

fn C.crypto_box_curve25519xsalsa20poly1305_publickeybytes() usize

pub fn crypto_box_curve25519xsalsa20poly1305_publickeybytes() usize {
	return C.crypto_box_curve25519xsalsa20poly1305_publickeybytes()
}

fn C.crypto_box_curve25519xsalsa20poly1305_secretkeybytes() usize

pub fn crypto_box_curve25519xsalsa20poly1305_secretkeybytes() usize {
	return C.crypto_box_curve25519xsalsa20poly1305_secretkeybytes()
}

fn C.crypto_box_curve25519xsalsa20poly1305_beforenmbytes() usize

pub fn crypto_box_curve25519xsalsa20poly1305_beforenmbytes() usize {
	return C.crypto_box_curve25519xsalsa20poly1305_beforenmbytes()
}

fn C.crypto_box_curve25519xsalsa20poly1305_noncebytes() usize

pub fn crypto_box_curve25519xsalsa20poly1305_noncebytes() usize {
	return C.crypto_box_curve25519xsalsa20poly1305_noncebytes()
}

fn C.crypto_box_curve25519xsalsa20poly1305_zerobytes() usize

pub fn crypto_box_curve25519xsalsa20poly1305_zerobytes() usize {
	return C.crypto_box_curve25519xsalsa20poly1305_zerobytes()
}

fn C.crypto_box_curve25519xsalsa20poly1305_boxzerobytes() usize

pub fn crypto_box_curve25519xsalsa20poly1305_boxzerobytes() usize {
	return C.crypto_box_curve25519xsalsa20poly1305_boxzerobytes()
}

fn C.crypto_box_curve25519xsalsa20poly1305_macbytes() usize

pub fn crypto_box_curve25519xsalsa20poly1305_macbytes() usize {
	return C.crypto_box_curve25519xsalsa20poly1305_macbytes()
}

fn C.crypto_box_curve25519xsalsa20poly1305_messagebytes_max() usize

pub fn crypto_box_curve25519xsalsa20poly1305_messagebytes_max() usize {
	return C.crypto_box_curve25519xsalsa20poly1305_messagebytes_max()
}

fn C.crypto_box_curve25519xchacha20poly1305_seed_keypair(pk &u8, sk &u8, seed &u8) int

pub fn crypto_box_curve25519xchacha20poly1305_seed_keypair(pk &u8, sk &u8, seed &u8) int {
	return C.crypto_box_curve25519xchacha20poly1305_seed_keypair(pk, sk, seed)
}

fn C.crypto_box_curve25519xchacha20poly1305_keypair(pk &u8, sk &u8) int

pub fn crypto_box_curve25519xchacha20poly1305_keypair(pk &u8, sk &u8) int {
	return C.crypto_box_curve25519xchacha20poly1305_keypair(pk, sk)
}

fn C.crypto_box_curve25519xchacha20poly1305_beforenm(k &u8, pk &u8, sk &u8) int

pub fn crypto_box_curve25519xchacha20poly1305_beforenm(k &u8, pk &u8, sk &u8) int {
	return C.crypto_box_curve25519xchacha20poly1305_beforenm(k, pk, sk)
}

fn C.crypto_box_curve25519xchacha20poly1305_detached_afternm(c &u8, mac &u8, m &u8, mlen u64, n &u8, k &u8) int

pub fn crypto_box_curve25519xchacha20poly1305_detached_afternm(c &u8, mac &u8, m &u8, mlen u64, n &u8, k &u8) int {
	return C.crypto_box_curve25519xchacha20poly1305_detached_afternm(c, mac, m, mlen,
		n, k)
}

fn C.crypto_box_curve25519xchacha20poly1305_detached(c &u8, mac &u8, m &u8, mlen u64, n &u8, pk &u8, sk &u8) int

pub fn crypto_box_curve25519xchacha20poly1305_detached(c &u8, mac &u8, m &u8, mlen u64, n &u8, pk &u8, sk &u8) int {
	return C.crypto_box_curve25519xchacha20poly1305_detached(c, mac, m, mlen, n, pk, sk)
}

fn C.crypto_box_curve25519xchacha20poly1305_easy_afternm(c &u8, m &u8, mlen u64, n &u8, k &u8) int

pub fn crypto_box_curve25519xchacha20poly1305_easy_afternm(c &u8, m &u8, mlen u64, n &u8, k &u8) int {
	return C.crypto_box_curve25519xchacha20poly1305_easy_afternm(c, m, mlen, n, k)
}

fn C.crypto_box_curve25519xchacha20poly1305_easy(c &u8, m &u8, mlen u64, n &u8, pk &u8, sk &u8) int

pub fn crypto_box_curve25519xchacha20poly1305_easy(c &u8, m &u8, mlen u64, n &u8, pk &u8, sk &u8) int {
	return C.crypto_box_curve25519xchacha20poly1305_easy(c, m, mlen, n, pk, sk)
}

fn C.crypto_box_curve25519xchacha20poly1305_open_detached_afternm(m &u8, c &u8, mac &u8, clen u64, n &u8, k &u8) int

pub fn crypto_box_curve25519xchacha20poly1305_open_detached_afternm(m &u8, c &u8, mac &u8, clen u64, n &u8, k &u8) int {
	return C.crypto_box_curve25519xchacha20poly1305_open_detached_afternm(m, c, mac, clen,
		n, k)
}

fn C.crypto_box_curve25519xchacha20poly1305_open_detached(m &u8, c &u8, mac &u8, clen u64, n &u8, pk &u8, sk &u8) int

pub fn crypto_box_curve25519xchacha20poly1305_open_detached(m &u8, c &u8, mac &u8, clen u64, n &u8, pk &u8, sk &u8) int {
	return C.crypto_box_curve25519xchacha20poly1305_open_detached(m, c, mac, clen, n,
		pk, sk)
}

fn C.crypto_box_curve25519xchacha20poly1305_open_easy_afternm(m &u8, c &u8, clen u64, n &u8, k &u8) int

pub fn crypto_box_curve25519xchacha20poly1305_open_easy_afternm(m &u8, c &u8, clen u64, n &u8, k &u8) int {
	return C.crypto_box_curve25519xchacha20poly1305_open_easy_afternm(m, c, clen, n, k)
}

fn C.crypto_box_curve25519xchacha20poly1305_open_easy(m &u8, c &u8, clen u64, n &u8, pk &u8, sk &u8) int

pub fn crypto_box_curve25519xchacha20poly1305_open_easy(m &u8, c &u8, clen u64, n &u8, pk &u8, sk &u8) int {
	return C.crypto_box_curve25519xchacha20poly1305_open_easy(m, c, clen, n, pk, sk)
}

fn C.crypto_box_curve25519xchacha20poly1305_seedbytes() usize

pub fn crypto_box_curve25519xchacha20poly1305_seedbytes() usize {
	return C.crypto_box_curve25519xchacha20poly1305_seedbytes()
}

fn C.crypto_box_curve25519xchacha20poly1305_publickeybytes() usize

pub fn crypto_box_curve25519xchacha20poly1305_publickeybytes() usize {
	return C.crypto_box_curve25519xchacha20poly1305_publickeybytes()
}

fn C.crypto_box_curve25519xchacha20poly1305_secretkeybytes() usize

pub fn crypto_box_curve25519xchacha20poly1305_secretkeybytes() usize {
	return C.crypto_box_curve25519xchacha20poly1305_secretkeybytes()
}

fn C.crypto_box_curve25519xchacha20poly1305_beforenmbytes() usize

pub fn crypto_box_curve25519xchacha20poly1305_beforenmbytes() usize {
	return C.crypto_box_curve25519xchacha20poly1305_beforenmbytes()
}

fn C.crypto_box_curve25519xchacha20poly1305_noncebytes() usize

pub fn crypto_box_curve25519xchacha20poly1305_noncebytes() usize {
	return C.crypto_box_curve25519xchacha20poly1305_noncebytes()
}

fn C.crypto_box_curve25519xchacha20poly1305_macbytes() usize

pub fn crypto_box_curve25519xchacha20poly1305_macbytes() usize {
	return C.crypto_box_curve25519xchacha20poly1305_macbytes()
}

fn C.crypto_box_curve25519xchacha20poly1305_messagebytes_max() usize

pub fn crypto_box_curve25519xchacha20poly1305_messagebytes_max() usize {
	return C.crypto_box_curve25519xchacha20poly1305_messagebytes_max()
}

fn C.crypto_box_curve25519xchacha20poly1305_seal(c &u8, m &u8, mlen u64, pk &u8) int

pub fn crypto_box_curve25519xchacha20poly1305_seal(c &u8, m &u8, mlen u64, pk &u8) int {
	return C.crypto_box_curve25519xchacha20poly1305_seal(c, m, mlen, pk)
}

fn C.crypto_box_curve25519xchacha20poly1305_seal_open(m &u8, c &u8, clen u64, pk &u8, sk &u8) int

pub fn crypto_box_curve25519xchacha20poly1305_seal_open(m &u8, c &u8, clen u64, pk &u8, sk &u8) int {
	return C.crypto_box_curve25519xchacha20poly1305_seal_open(m, c, clen, pk, sk)
}

fn C.crypto_box_curve25519xchacha20poly1305_sealbytes() usize

pub fn crypto_box_curve25519xchacha20poly1305_sealbytes() usize {
	return C.crypto_box_curve25519xchacha20poly1305_sealbytes()
}

fn C.crypto_box_primitive() &char

pub fn crypto_box_primitive() &char {
	return &char(C.crypto_box_primitive())
}

fn C.crypto_box_seed_keypair(pk &u8, sk &u8, seed &u8) int

pub fn crypto_box_seed_keypair(pk &u8, sk &u8, seed &u8) int {
	return C.crypto_box_seed_keypair(pk, sk, seed)
}

fn C.crypto_box_keypair(pk &u8, sk &u8) int

pub fn crypto_box_keypair(pk &u8, sk &u8) int {
	return C.crypto_box_keypair(pk, sk)
}

fn C.crypto_box_beforenm(k &u8, pk &u8, sk &u8) int

pub fn crypto_box_beforenm(k &u8, pk &u8, sk &u8) int {
	return C.crypto_box_beforenm(k, pk, sk)
}

fn C.crypto_box_afternm(c &u8, m &u8, mlen u64, n &u8, k &u8) int

pub fn crypto_box_afternm(c &u8, m &u8, mlen u64, n &u8, k &u8) int {
	return C.crypto_box_afternm(c, m, mlen, n, k)
}

fn C.crypto_box_open_afternm(m &u8, c &u8, clen u64, n &u8, k &u8) int

pub fn crypto_box_open_afternm(m &u8, c &u8, clen u64, n &u8, k &u8) int {
	return C.crypto_box_open_afternm(m, c, clen, n, k)
}

fn C.crypto_box(c &u8, m &u8, mlen u64, n &u8, pk &u8, sk &u8) int

pub fn crypto_box(c &u8, m &u8, mlen u64, n &u8, pk &u8, sk &u8) int {
	return C.crypto_box(c, m, mlen, n, pk, sk)
}

fn C.crypto_box_open(m &u8, c &u8, clen u64, n &u8, pk &u8, sk &u8) int

pub fn crypto_box_open(m &u8, c &u8, clen u64, n &u8, pk &u8, sk &u8) int {
	return C.crypto_box_open(m, c, clen, n, pk, sk)
}

fn C.sodium_bin2hex(hex &char, hex_maxlen usize, bin &u8, bin_len usize) &char

pub fn sodium_bin2hex(hex &char, hex_maxlen usize, bin &u8, bin_len usize) &char {
	return &char(C.sodium_bin2hex(hex, hex_maxlen, bin, bin_len))
}

fn C.sodium_hex2bin(bin &u8, bin_maxlen usize, hex &char, hex_len usize, ignore &char, bin_len &usize, hex_end &&char) int

pub fn sodium_hex2bin(bin &u8, bin_maxlen usize, hex &char, hex_len usize, ignore &char, bin_len &usize, hex_end &&char) int {
	return C.sodium_hex2bin(bin, bin_maxlen, hex, hex_len, ignore, bin_len, voidptr(hex_end))
}

fn C.sodium_base64_encoded_len(bin_len usize, variant int) usize

pub fn sodium_base64_encoded_len(bin_len usize, variant int) usize {
	return C.sodium_base64_encoded_len(bin_len, variant)
}

fn C.sodium_bin2base64(b64 &char, b64_maxlen usize, bin &u8, bin_len usize, variant int) &char

pub fn sodium_bin2base64(b64 &char, b64_maxlen usize, bin &u8, bin_len usize, variant int) &char {
	return &char(C.sodium_bin2base64(b64, b64_maxlen, bin, bin_len, variant))
}

fn C.sodium_base642bin(bin &u8, bin_maxlen usize, b64 &char, b64_len usize, ignore &char, bin_len &usize, b64_end &&char, variant int) int

pub fn sodium_base642bin(bin &u8, bin_maxlen usize, b64 &char, b64_len usize, ignore &char, bin_len &usize, b64_end &&char, variant int) int {
	return C.sodium_base642bin(bin, bin_maxlen, b64, b64_len, ignore, bin_len, voidptr(b64_end),
		variant)
}

// struct decl name="CPUFeatures_"
// typedef struct
// ['referenced', 'CPUFeatures', 'struct CPUFeatures_:struct CPUFeatures_']
struct CPUFeatures {
	initialized   int
	has_neon      int
	has_armcrypto int
	has_sse2      int
	has_sse3      int
	has_ssse3     int
	has_sse41     int
	has_avx       int
	has_avx2      int
	has_avx512f   int
	has_pclmul    int
	has_aesni     int
	has_rdrand    int
}

fn C.sodium_runtime_has_neon() int

pub fn sodium_runtime_has_neon() int {
	return C.sodium_runtime_has_neon()
}

fn C.sodium_runtime_has_sse2() int

pub fn sodium_runtime_has_sse2() int {
	return C.sodium_runtime_has_sse2()
}

fn C.sodium_runtime_has_sse3() int

pub fn sodium_runtime_has_sse3() int {
	return C.sodium_runtime_has_sse3()
}

fn C.sodium_runtime_has_ssse3() int

pub fn sodium_runtime_has_ssse3() int {
	return C.sodium_runtime_has_ssse3()
}

fn C.sodium_runtime_has_sse41() int

pub fn sodium_runtime_has_sse41() int {
	return C.sodium_runtime_has_sse41()
}

fn C.sodium_runtime_has_avx() int

pub fn sodium_runtime_has_avx() int {
	return C.sodium_runtime_has_avx()
}

fn C.sodium_runtime_has_avx2() int

pub fn sodium_runtime_has_avx2() int {
	return C.sodium_runtime_has_avx2()
}

fn C.sodium_runtime_has_avx512f() int

pub fn sodium_runtime_has_avx512f() int {
	return C.sodium_runtime_has_avx512f()
}

fn C.sodium_runtime_has_pclmul() int

pub fn sodium_runtime_has_pclmul() int {
	return C.sodium_runtime_has_pclmul()
}

fn C.sodium_runtime_has_aesni() int

pub fn sodium_runtime_has_aesni() int {
	return C.sodium_runtime_has_aesni()
}

fn C.sodium_runtime_has_rdrand() int

pub fn sodium_runtime_has_rdrand() int {
	return C.sodium_runtime_has_rdrand()
}

fn C.sodium_init() int

pub fn sodium_init() int {
	return C.sodium_init()
}

fn C.sodium_misuse()

pub fn sodium_misuse() {
	C.sodium_misuse()
}

fn C.sodium_set_misuse_handler(handler fn ()) int

pub fn sodium_set_misuse_handler(handler fn ()) int {
	return C.sodium_set_misuse_handler(handler)
}

fn C.sodium_memzero(pnt voidptr, len usize)

pub fn sodium_memzero(pnt voidptr, len usize) {
	C.sodium_memzero(pnt, len)
}

fn C.sodium_stackzero(len usize)

pub fn sodium_stackzero(len usize) {
	C.sodium_stackzero(len)
}

fn C.sodium_memcmp(b1_ voidptr, b2_ voidptr, len usize) int

pub fn sodium_memcmp(b1_ voidptr, b2_ voidptr, len usize) int {
	return C.sodium_memcmp(b1_, b2_, len)
}

fn C.sodium_compare(b1_ &u8, b2_ &u8, len usize) int

pub fn sodium_compare(b1_ &u8, b2_ &u8, len usize) int {
	return C.sodium_compare(b1_, b2_, len)
}

fn C.sodium_is_zero(n &u8, nlen usize) int

pub fn sodium_is_zero(n &u8, nlen usize) int {
	return C.sodium_is_zero(n, nlen)
}

fn C.sodium_increment(n &u8, nlen usize)

pub fn sodium_increment(n &u8, nlen usize) {
	C.sodium_increment(n, nlen)
}

fn C.sodium_add(a &u8, b &u8, len usize)

pub fn sodium_add(a &u8, b &u8, len usize) {
	C.sodium_add(a, b, len)
}

fn C.sodium_sub(a &u8, b &u8, len usize)

pub fn sodium_sub(a &u8, b &u8, len usize) {
	C.sodium_sub(a, b, len)
}

fn C.sodium_mlock(addr voidptr, len usize) int

pub fn sodium_mlock(addr voidptr, len usize) int {
	return C.sodium_mlock(addr, len)
}

fn C.sodium_munlock(addr voidptr, len usize) int

pub fn sodium_munlock(addr voidptr, len usize) int {
	return C.sodium_munlock(addr, len)
}

fn C.sodium_malloc(size usize) voidptr

pub fn sodium_malloc(size usize) voidptr {
	return C.sodium_malloc(size)
}

fn C.sodium_allocarray(count usize, size usize) voidptr

pub fn sodium_allocarray(count usize, size usize) voidptr {
	return C.sodium_allocarray(count, size)
}

fn C.sodium_free(ptr voidptr)

pub fn sodium_free(ptr voidptr) {
	C.sodium_free(ptr)
}

fn C.sodium_mprotect_noaccess(ptr voidptr) int

pub fn sodium_mprotect_noaccess(ptr voidptr) int {
	return C.sodium_mprotect_noaccess(ptr)
}

fn C.sodium_mprotect_readonly(ptr voidptr) int

pub fn sodium_mprotect_readonly(ptr voidptr) int {
	return C.sodium_mprotect_readonly(ptr)
}

fn C.sodium_mprotect_readwrite(ptr voidptr) int

pub fn sodium_mprotect_readwrite(ptr voidptr) int {
	return C.sodium_mprotect_readwrite(ptr)
}

fn C.sodium_pad(padded_buflen_p &usize, buf &u8, unpadded_buflen usize, blocksize usize, max_buflen usize) int

pub fn sodium_pad(padded_buflen_p &usize, buf &u8, unpadded_buflen usize, blocksize usize, max_buflen usize) int {
	return C.sodium_pad(padded_buflen_p, buf, unpadded_buflen, blocksize, max_buflen)
}

fn C.sodium_unpad(unpadded_buflen_p &usize, buf &u8, padded_buflen usize, blocksize usize) int

pub fn sodium_unpad(unpadded_buflen_p &usize, buf &u8, padded_buflen usize, blocksize usize) int {
	return C.sodium_unpad(unpadded_buflen_p, buf, padded_buflen, blocksize)
}

fn C.sodium_version_string() &char

pub fn sodium_version_string() &char {
	return &char(C.sodium_version_string())
}

fn C.sodium_library_version_major() int

pub fn sodium_library_version_major() int {
	return C.sodium_library_version_major()
}

fn C.sodium_library_version_minor() int

pub fn sodium_library_version_minor() int {
	return C.sodium_library_version_minor()
}

fn C.sodium_library_minimal() int

pub fn sodium_library_minimal() int {
	return C.sodium_library_minimal()
}

fn C.crypto_stream_xchacha20_keybytes() usize

pub fn crypto_stream_xchacha20_keybytes() usize {
	return C.crypto_stream_xchacha20_keybytes()
}

fn C.crypto_stream_xchacha20_noncebytes() usize

pub fn crypto_stream_xchacha20_noncebytes() usize {
	return C.crypto_stream_xchacha20_noncebytes()
}

fn C.crypto_stream_xchacha20_messagebytes_max() usize

pub fn crypto_stream_xchacha20_messagebytes_max() usize {
	return C.crypto_stream_xchacha20_messagebytes_max()
}

fn C.crypto_stream_xchacha20(c &u8, clen u64, n &u8, k &u8) int

pub fn crypto_stream_xchacha20(c &u8, clen u64, n &u8, k &u8) int {
	return C.crypto_stream_xchacha20(c, clen, n, k)
}

fn C.crypto_stream_xchacha20_xor_ic(c &u8, m &u8, mlen u64, n &u8, ic u64, k &u8) int

pub fn crypto_stream_xchacha20_xor_ic(c &u8, m &u8, mlen u64, n &u8, ic u64, k &u8) int {
	return C.crypto_stream_xchacha20_xor_ic(c, m, mlen, n, ic, k)
}

fn C.crypto_stream_xchacha20_xor(c &u8, m &u8, mlen u64, n &u8, k &u8) int

pub fn crypto_stream_xchacha20_xor(c &u8, m &u8, mlen u64, n &u8, k &u8) int {
	return C.crypto_stream_xchacha20_xor(c, m, mlen, n, k)
}

// struct decl name="crypto_stream_chacha20_implementation"
// typedef struct
// ['crypto_stream_chacha20_implementation', 'struct crypto_stream_chacha20_implementation:struct crypto_stream_chacha20_implementation']
/*
struct crypto_stream_chacha20_implementation {
	stream fn (byteptr, u64, byteptr, byteptr) int
	stream_ietf_ext fn (byteptr, u64, byteptr, byteptr) int
	stream_xor_ic fn (byteptr, byteptr, u64, byteptr, u64, byteptr) int
	stream_ietf_ext_xor_ic fn (byteptr, byteptr, u64, byteptr, u32, byteptr) int
}
// struct decl name="chacha_ctx"
// typedef struct
// ['referenced', 'chacha_ctx', 'struct chacha_ctx:struct chacha_ctx']
struct chacha_ctx {
	input [16]u32
}
*/
// struct decl name="crypto_stream_chacha20_implementation"
// typedef struct
// ['referenced', 'crypto_stream_chacha20_implementation', 'struct crypto_stream_chacha20_implementation:struct crypto_stream_chacha20_implementation']
fn C.crypto_stream_chacha20(c &u8, clen u64, n &u8, k &u8) int

pub fn crypto_stream_chacha20(c &u8, clen u64, n &u8, k &u8) int {
	return C.crypto_stream_chacha20(c, clen, n, k)
}

fn C.crypto_stream_chacha20_xor_ic(c &u8, m &u8, mlen u64, n &u8, ic u64, k &u8) int

pub fn crypto_stream_chacha20_xor_ic(c &u8, m &u8, mlen u64, n &u8, ic u64, k &u8) int {
	return C.crypto_stream_chacha20_xor_ic(c, m, mlen, n, ic, k)
}

fn C.crypto_stream_chacha20_xor(c &u8, m &u8, mlen u64, n &u8, k &u8) int

pub fn crypto_stream_chacha20_xor(c &u8, m &u8, mlen u64, n &u8, k &u8) int {
	return C.crypto_stream_chacha20_xor(c, m, mlen, n, k)
}

fn C.crypto_stream_chacha20_ietf(c &u8, clen u64, n &u8, k &u8) int

pub fn crypto_stream_chacha20_ietf(c &u8, clen u64, n &u8, k &u8) int {
	return C.crypto_stream_chacha20_ietf(c, clen, n, k)
}

fn C.crypto_stream_chacha20_ietf_xor_ic(c &u8, m &u8, mlen u64, n &u8, ic u32, k &u8) int

pub fn crypto_stream_chacha20_ietf_xor_ic(c &u8, m &u8, mlen u64, n &u8, ic u32, k &u8) int {
	return C.crypto_stream_chacha20_ietf_xor_ic(c, m, mlen, n, ic, k)
}

fn C.crypto_stream_chacha20_ietf_xor(c &u8, m &u8, mlen u64, n &u8, k &u8) int

pub fn crypto_stream_chacha20_ietf_xor(c &u8, m &u8, mlen u64, n &u8, k &u8) int {
	return C.crypto_stream_chacha20_ietf_xor(c, m, mlen, n, k)
}

// struct decl name="crypto_stream_salsa20_implementation"
// typedef struct
// ['crypto_stream_salsa20_implementation', 'struct crypto_stream_salsa20_implementation:struct crypto_stream_salsa20_implementation']
/*
struct crypto_stream_salsa20_implementation {
	stream fn (byteptr, u64, byteptr, byteptr) int
	stream_xor_ic fn (byteptr, byteptr, u64, byteptr, u64, byteptr) int
}
*/
// struct decl name="crypto_stream_salsa20_implementation"
// typedef struct
// ['referenced', 'crypto_stream_salsa20_implementation', 'struct crypto_stream_salsa20_implementation:struct crypto_stream_salsa20_implementation']
fn C.crypto_stream_salsa20(c &u8, clen u64, n &u8, k &u8) int

pub fn crypto_stream_salsa20(c &u8, clen u64, n &u8, k &u8) int {
	return C.crypto_stream_salsa20(c, clen, n, k)
}

fn C.crypto_stream_salsa20_xor_ic(c &u8, m &u8, mlen u64, n &u8, ic u64, k &u8) int

pub fn crypto_stream_salsa20_xor_ic(c &u8, m &u8, mlen u64, n &u8, ic u64, k &u8) int {
	return C.crypto_stream_salsa20_xor_ic(c, m, mlen, n, ic, k)
}

fn C.crypto_stream_salsa20_xor(c &u8, m &u8, mlen u64, n &u8, k &u8) int

pub fn crypto_stream_salsa20_xor(c &u8, m &u8, mlen u64, n &u8, k &u8) int {
	return C.crypto_stream_salsa20_xor(c, m, mlen, n, k)
}

// struct decl name="crypto_stream_salsa20_implementation"
// typedef struct
// ['crypto_stream_salsa20_implementation', 'struct crypto_stream_salsa20_implementation:struct crypto_stream_salsa20_implementation']
fn C.crypto_stream_primitive() &char

pub fn crypto_stream_primitive() &char {
	return &char(C.crypto_stream_primitive())
}

fn C.crypto_stream(c &u8, clen u64, n &u8, k &u8) int

pub fn crypto_stream(c &u8, clen u64, n &u8, k &u8) int {
	return C.crypto_stream(c, clen, n, k)
}

fn C.crypto_stream_xor(c &u8, m &u8, mlen u64, n &u8, k &u8) int

pub fn crypto_stream_xor(c &u8, m &u8, mlen u64, n &u8, k &u8) int {
	return C.crypto_stream_xor(c, m, mlen, n, k)
}

fn C.crypto_stream_salsa2012(c &u8, clen u64, n &u8, k &u8) int

pub fn crypto_stream_salsa2012(c &u8, clen u64, n &u8, k &u8) int {
	return C.crypto_stream_salsa2012(c, clen, n, k)
}

fn C.crypto_stream_salsa2012_xor(c &u8, m &u8, mlen u64, n &u8, k &u8) int

pub fn crypto_stream_salsa2012_xor(c &u8, m &u8, mlen u64, n &u8, k &u8) int {
	return C.crypto_stream_salsa2012_xor(c, m, mlen, n, k)
}

// fn C.crypto_stream_salsa208(c &u8, clen u64, n &u8, k &u8) int

// pub fn crypto_stream_salsa208(c &u8, clen u64, n &u8, k &u8) int {
//	return C.crypto_stream_salsa208(c, clen, n, k)
//}

// fn C.crypto_stream_salsa208_xor(c &u8, m &u8, mlen u64, n &u8, k &u8) int

// pub fn crypto_stream_salsa208_xor(c &u8, m &u8, mlen u64, n &u8, k &u8) int {
//	return C.crypto_stream_salsa208_xor(c, m, mlen, n, k)
//}

fn C.crypto_stream_xsalsa20(c &u8, clen u64, n &u8, k &u8) int

pub fn crypto_stream_xsalsa20(c &u8, clen u64, n &u8, k &u8) int {
	return C.crypto_stream_xsalsa20(c, clen, n, k)
}

fn C.crypto_stream_xsalsa20_xor(c &u8, m &u8, mlen u64, n &u8, k &u8) int

pub fn crypto_stream_xsalsa20_xor(c &u8, m &u8, mlen u64, n &u8, k &u8) int {
	return C.crypto_stream_xsalsa20_xor(c, m, mlen, n, k)
}

fn C.crypto_hash_sha512(out &u8, in_ &u8, inlen u64) int

pub fn crypto_hash_sha512(out &u8, in_ &u8, inlen u64) int {
	return C.crypto_hash_sha512(out, in_, inlen)
}

fn C.crypto_hash_sha256(out &u8, in_ &u8, inlen u64) int

pub fn crypto_hash_sha256(out &u8, in_ &u8, inlen u64) int {
	return C.crypto_hash_sha256(out, in_, inlen)
}

fn C.crypto_hash(out &u8, in_ &u8, inlen u64) int

pub fn crypto_hash(out &u8, in_ &u8, inlen u64) int {
	return C.crypto_hash(out, in_, inlen)
}

fn C.crypto_hash_primitive() &char

pub fn crypto_hash_primitive() &char {
	return &char(C.crypto_hash_primitive())
}

fn C.crypto_aead_xchacha20poly1305_ietf_encrypt_detached(c &u8, mac &u8, maclen_p &C.UNSIGNED_LONG_LONG, m &u8, mlen u64, ad &u8, adlen u64, nsec &u8, npub &u8, k &u8) int

pub fn crypto_aead_xchacha20poly1305_ietf_encrypt_detached(c &u8, mac &u8, maclen_p &u64, m &u8, mlen u64, ad &u8, adlen u64, nsec &u8, npub &u8, k &u8) int {
	return C.crypto_aead_xchacha20poly1305_ietf_encrypt_detached(c, mac, C.ULLCAST(maclen_p),
		m, mlen, ad, adlen, nsec, npub, k)
}

fn C.crypto_aead_xchacha20poly1305_ietf_encrypt(c &u8, clen_p &C.UNSIGNED_LONG_LONG, m &u8, mlen u64, ad &u8, adlen u64, nsec &u8, npub &u8, k &u8) int

pub fn crypto_aead_xchacha20poly1305_ietf_encrypt(c &u8, clen_p &u64, m &u8, mlen u64, ad &u8, adlen u64, nsec &u8, npub &u8, k &u8) int {
	return C.crypto_aead_xchacha20poly1305_ietf_encrypt(c, C.ULLCAST(clen_p), m, mlen,
		ad, adlen, nsec, npub, k)
}

fn C.crypto_aead_xchacha20poly1305_ietf_decrypt_detached(m &u8, nsec &u8, c &u8, clen u64, mac &u8, ad &u8, adlen u64, npub &u8, k &u8) int

pub fn crypto_aead_xchacha20poly1305_ietf_decrypt_detached(m &u8, nsec &u8, c &u8, clen u64, mac &u8, ad &u8, adlen u64, npub &u8, k &u8) int {
	return C.crypto_aead_xchacha20poly1305_ietf_decrypt_detached(m, nsec, c, clen, mac,
		ad, adlen, npub, k)
}

fn C.crypto_aead_xchacha20poly1305_ietf_decrypt(m &u8, mlen_p &C.UNSIGNED_LONG_LONG, nsec &u8, c &u8, clen u64, ad &u8, adlen u64, npub &u8, k &u8) int

pub fn crypto_aead_xchacha20poly1305_ietf_decrypt(m &u8, mlen_p &u64, nsec &u8, c &u8, clen u64, ad &u8, adlen u64, npub &u8, k &u8) int {
	return C.crypto_aead_xchacha20poly1305_ietf_decrypt(m, C.ULLCAST(mlen_p), nsec, c,
		clen, ad, adlen, npub, k)
}

fn C.crypto_aead_xchacha20poly1305_ietf_keybytes() usize

pub fn crypto_aead_xchacha20poly1305_ietf_keybytes() usize {
	return C.crypto_aead_xchacha20poly1305_ietf_keybytes()
}

fn C.crypto_aead_xchacha20poly1305_ietf_npubbytes() usize

pub fn crypto_aead_xchacha20poly1305_ietf_npubbytes() usize {
	return C.crypto_aead_xchacha20poly1305_ietf_npubbytes()
}

fn C.crypto_aead_xchacha20poly1305_ietf_nsecbytes() usize

pub fn crypto_aead_xchacha20poly1305_ietf_nsecbytes() usize {
	return C.crypto_aead_xchacha20poly1305_ietf_nsecbytes()
}

fn C.crypto_aead_xchacha20poly1305_ietf_abytes() usize

pub fn crypto_aead_xchacha20poly1305_ietf_abytes() usize {
	return C.crypto_aead_xchacha20poly1305_ietf_abytes()
}

fn C.crypto_aead_xchacha20poly1305_ietf_messagebytes_max() usize

pub fn crypto_aead_xchacha20poly1305_ietf_messagebytes_max() usize {
	return C.crypto_aead_xchacha20poly1305_ietf_messagebytes_max()
}

fn C.crypto_aead_aes256gcm_encrypt_detached(c &u8, mac &u8, maclen_p &C.UNSIGNED_LONG_LONG, m &u8, mlen u64, ad &u8, adlen u64, nsec &u8, npub &u8, k &u8) int

pub fn crypto_aead_aes256gcm_encrypt_detached(c &u8, mac &u8, maclen_p &u64, m &u8, mlen u64, ad &u8, adlen u64, nsec &u8, npub &u8, k &u8) int {
	return C.crypto_aead_aes256gcm_encrypt_detached(c, mac, C.ULLCAST(maclen_p), m, mlen,
		ad, adlen, nsec, npub, k)
}

fn C.crypto_aead_aes256gcm_encrypt(c &u8, clen_p &C.UNSIGNED_LONG_LONG, m &u8, mlen u64, ad &u8, adlen u64, nsec &u8, npub &u8, k &u8) int

pub fn crypto_aead_aes256gcm_encrypt(c &u8, clen_p &u64, m &u8, mlen u64, ad &u8, adlen u64, nsec &u8, npub &u8, k &u8) int {
	return C.crypto_aead_aes256gcm_encrypt(c, C.ULLCAST(clen_p), m, mlen, ad, adlen, nsec,
		npub, k)
}

fn C.crypto_aead_aes256gcm_decrypt_detached(m &u8, nsec &u8, c &u8, clen u64, mac &u8, ad &u8, adlen u64, npub &u8, k &u8) int

pub fn crypto_aead_aes256gcm_decrypt_detached(m &u8, nsec &u8, c &u8, clen u64, mac &u8, ad &u8, adlen u64, npub &u8, k &u8) int {
	return C.crypto_aead_aes256gcm_decrypt_detached(m, nsec, c, clen, mac, ad, adlen,
		npub, k)
}

fn C.crypto_aead_aes256gcm_decrypt(m &u8, mlen_p &C.UNSIGNED_LONG_LONG, nsec &u8, c &u8, clen u64, ad &u8, adlen u64, npub &u8, k &u8) int

pub fn crypto_aead_aes256gcm_decrypt(m &u8, mlen_p &u64, nsec &u8, c &u8, clen u64, ad &u8, adlen u64, npub &u8, k &u8) int {
	return C.crypto_aead_aes256gcm_decrypt(m, C.ULLCAST(mlen_p), nsec, c, clen, ad, adlen,
		npub, k)
}

fn C.crypto_aead_aes256gcm_is_available() int

pub fn crypto_aead_aes256gcm_is_available() int {
	return C.crypto_aead_aes256gcm_is_available()
}

fn C.crypto_aead_aes256gcm_keybytes() usize

pub fn crypto_aead_aes256gcm_keybytes() usize {
	return C.crypto_aead_aes256gcm_keybytes()
}

fn C.crypto_aead_aes256gcm_nsecbytes() usize

pub fn crypto_aead_aes256gcm_nsecbytes() usize {
	return C.crypto_aead_aes256gcm_nsecbytes()
}

fn C.crypto_aead_aes256gcm_npubbytes() usize

pub fn crypto_aead_aes256gcm_npubbytes() usize {
	return C.crypto_aead_aes256gcm_npubbytes()
}

fn C.crypto_aead_aes256gcm_abytes() usize

pub fn crypto_aead_aes256gcm_abytes() usize {
	return C.crypto_aead_aes256gcm_abytes()
}

fn C.crypto_aead_aes256gcm_statebytes() usize

pub fn crypto_aead_aes256gcm_statebytes() usize {
	return C.crypto_aead_aes256gcm_statebytes()
}

fn C.crypto_aead_aes256gcm_messagebytes_max() usize

pub fn crypto_aead_aes256gcm_messagebytes_max() usize {
	return C.crypto_aead_aes256gcm_messagebytes_max()
}

fn C.crypto_aead_chacha20poly1305_encrypt_detached(c &u8, mac &u8, maclen_p &C.UNSIGNED_LONG_LONG, m &u8, mlen u64, ad &u8, adlen u64, nsec &u8, npub &u8, k &u8) int

pub fn crypto_aead_chacha20poly1305_encrypt_detached(c &u8, mac &u8, maclen_p &u64, m &u8, mlen u64, ad &u8, adlen u64, nsec &u8, npub &u8, k &u8) int {
	return C.crypto_aead_chacha20poly1305_encrypt_detached(c, mac, C.ULLCAST(maclen_p),
		m, mlen, ad, adlen, nsec, npub, k)
}

fn C.crypto_aead_chacha20poly1305_encrypt(c &u8, clen_p &C.UNSIGNED_LONG_LONG, m &u8, mlen u64, ad &u8, adlen u64, nsec &u8, npub &u8, k &u8) int

pub fn crypto_aead_chacha20poly1305_encrypt(c &u8, clen_p &u64, m &u8, mlen u64, ad &u8, adlen u64, nsec &u8, npub &u8, k &u8) int {
	return C.crypto_aead_chacha20poly1305_encrypt(c, C.ULLCAST(clen_p), m, mlen, ad, adlen,
		nsec, npub, k)
}

fn C.crypto_aead_chacha20poly1305_ietf_encrypt_detached(c &u8, mac &u8, maclen_p &C.UNSIGNED_LONG_LONG, m &u8, mlen u64, ad &u8, adlen u64, nsec &u8, npub &u8, k &u8) int

pub fn crypto_aead_chacha20poly1305_ietf_encrypt_detached(c &u8, mac &u8, maclen_p &u64, m &u8, mlen u64, ad &u8, adlen u64, nsec &u8, npub &u8, k &u8) int {
	return C.crypto_aead_chacha20poly1305_ietf_encrypt_detached(c, mac, C.ULLCAST(maclen_p),
		m, mlen, ad, adlen, nsec, npub, k)
}

fn C.crypto_aead_chacha20poly1305_ietf_encrypt(c &u8, clen_p &C.UNSIGNED_LONG_LONG, m &u8, mlen u64, ad &u8, adlen u64, nsec &u8, npub &u8, k &u8) int

pub fn crypto_aead_chacha20poly1305_ietf_encrypt(c &u8, clen_p &u64, m &u8, mlen u64, ad &u8, adlen u64, nsec &u8, npub &u8, k &u8) int {
	return C.crypto_aead_chacha20poly1305_ietf_encrypt(c, C.ULLCAST(clen_p), m, mlen,
		ad, adlen, nsec, npub, k)
}

fn C.crypto_aead_chacha20poly1305_decrypt_detached(m &u8, nsec &u8, c &u8, clen u64, mac &u8, ad &u8, adlen u64, npub &u8, k &u8) int

pub fn crypto_aead_chacha20poly1305_decrypt_detached(m &u8, nsec &u8, c &u8, clen u64, mac &u8, ad &u8, adlen u64, npub &u8, k &u8) int {
	return C.crypto_aead_chacha20poly1305_decrypt_detached(m, nsec, c, clen, mac, ad,
		adlen, npub, k)
}

fn C.crypto_aead_chacha20poly1305_decrypt(m &u8, mlen_p &C.UNSIGNED_LONG_LONG, nsec &u8, c &u8, clen u64, ad &u8, adlen u64, npub &u8, k &u8) int

pub fn crypto_aead_chacha20poly1305_decrypt(m &u8, mlen_p &u64, nsec &u8, c &u8, clen u64, ad &u8, adlen u64, npub &u8, k &u8) int {
	return C.crypto_aead_chacha20poly1305_decrypt(m, C.ULLCAST(mlen_p), nsec, c, clen,
		ad, adlen, npub, k)
}

fn C.crypto_aead_chacha20poly1305_ietf_decrypt_detached(m &u8, nsec &u8, c &u8, clen u64, mac &u8, ad &u8, adlen u64, npub &u8, k &u8) int

pub fn crypto_aead_chacha20poly1305_ietf_decrypt_detached(m &u8, nsec &u8, c &u8, clen u64, mac &u8, ad &u8, adlen u64, npub &u8, k &u8) int {
	return C.crypto_aead_chacha20poly1305_ietf_decrypt_detached(m, nsec, c, clen, mac,
		ad, adlen, npub, k)
}

fn C.crypto_aead_chacha20poly1305_ietf_decrypt(m &u8, mlen_p &C.UNSIGNED_LONG_LONG, nsec &u8, c &u8, clen u64, ad &u8, adlen u64, npub &u8, k &u8) int

pub fn crypto_aead_chacha20poly1305_ietf_decrypt(m &u8, mlen_p &u64, nsec &u8, c &u8, clen u64, ad &u8, adlen u64, npub &u8, k &u8) int {
	return C.crypto_aead_chacha20poly1305_ietf_decrypt(m, C.ULLCAST(mlen_p), nsec, c,
		clen, ad, adlen, npub, k)
}

fn C.crypto_aead_chacha20poly1305_ietf_keybytes() usize

pub fn crypto_aead_chacha20poly1305_ietf_keybytes() usize {
	return C.crypto_aead_chacha20poly1305_ietf_keybytes()
}

fn C.crypto_aead_chacha20poly1305_ietf_npubbytes() usize

pub fn crypto_aead_chacha20poly1305_ietf_npubbytes() usize {
	return C.crypto_aead_chacha20poly1305_ietf_npubbytes()
}

fn C.crypto_aead_chacha20poly1305_ietf_nsecbytes() usize

pub fn crypto_aead_chacha20poly1305_ietf_nsecbytes() usize {
	return C.crypto_aead_chacha20poly1305_ietf_nsecbytes()
}

fn C.crypto_aead_chacha20poly1305_ietf_abytes() usize

pub fn crypto_aead_chacha20poly1305_ietf_abytes() usize {
	return C.crypto_aead_chacha20poly1305_ietf_abytes()
}

fn C.crypto_aead_chacha20poly1305_ietf_messagebytes_max() usize

pub fn crypto_aead_chacha20poly1305_ietf_messagebytes_max() usize {
	return C.crypto_aead_chacha20poly1305_ietf_messagebytes_max()
}

fn C.crypto_aead_chacha20poly1305_keybytes() usize

pub fn crypto_aead_chacha20poly1305_keybytes() usize {
	return C.crypto_aead_chacha20poly1305_keybytes()
}

fn C.crypto_aead_chacha20poly1305_npubbytes() usize

pub fn crypto_aead_chacha20poly1305_npubbytes() usize {
	return C.crypto_aead_chacha20poly1305_npubbytes()
}

fn C.crypto_aead_chacha20poly1305_nsecbytes() usize

pub fn crypto_aead_chacha20poly1305_nsecbytes() usize {
	return C.crypto_aead_chacha20poly1305_nsecbytes()
}

fn C.crypto_aead_chacha20poly1305_abytes() usize

pub fn crypto_aead_chacha20poly1305_abytes() usize {
	return C.crypto_aead_chacha20poly1305_abytes()
}

fn C.crypto_aead_chacha20poly1305_messagebytes_max() usize

pub fn crypto_aead_chacha20poly1305_messagebytes_max() usize {
	return C.crypto_aead_chacha20poly1305_messagebytes_max()
}

fn C.crypto_secretstream_xchacha20poly1305_statebytes() usize

pub fn crypto_secretstream_xchacha20poly1305_statebytes() usize {
	return C.crypto_secretstream_xchacha20poly1305_statebytes()
}

fn C.crypto_secretstream_xchacha20poly1305_abytes() usize

pub fn crypto_secretstream_xchacha20poly1305_abytes() usize {
	return C.crypto_secretstream_xchacha20poly1305_abytes()
}

fn C.crypto_secretstream_xchacha20poly1305_headerbytes() usize

pub fn crypto_secretstream_xchacha20poly1305_headerbytes() usize {
	return C.crypto_secretstream_xchacha20poly1305_headerbytes()
}

fn C.crypto_secretstream_xchacha20poly1305_keybytes() usize

pub fn crypto_secretstream_xchacha20poly1305_keybytes() usize {
	return C.crypto_secretstream_xchacha20poly1305_keybytes()
}

fn C.crypto_secretstream_xchacha20poly1305_messagebytes_max() usize

pub fn crypto_secretstream_xchacha20poly1305_messagebytes_max() usize {
	return C.crypto_secretstream_xchacha20poly1305_messagebytes_max()
}

fn C.crypto_secretstream_xchacha20poly1305_tag_message() u8

pub fn crypto_secretstream_xchacha20poly1305_tag_message() u8 {
	return C.crypto_secretstream_xchacha20poly1305_tag_message()
}

fn C.crypto_secretstream_xchacha20poly1305_tag_push() u8

pub fn crypto_secretstream_xchacha20poly1305_tag_push() u8 {
	return C.crypto_secretstream_xchacha20poly1305_tag_push()
}

fn C.crypto_secretstream_xchacha20poly1305_tag_rekey() u8

pub fn crypto_secretstream_xchacha20poly1305_tag_rekey() u8 {
	return C.crypto_secretstream_xchacha20poly1305_tag_rekey()
}

fn C.crypto_secretstream_xchacha20poly1305_tag_final() u8

pub fn crypto_secretstream_xchacha20poly1305_tag_final() u8 {
	return C.crypto_secretstream_xchacha20poly1305_tag_final()
}

fn C.crypto_core_salsa20(out &u8, in_ &u8, k &u8, c &u8) int

pub fn crypto_core_salsa20(out &u8, in_ &u8, k &u8, c &u8) int {
	return C.crypto_core_salsa20(out, in_, k, c)
}

fn C.crypto_core_salsa20_outputbytes() usize

pub fn crypto_core_salsa20_outputbytes() usize {
	return C.crypto_core_salsa20_outputbytes()
}

fn C.crypto_core_salsa20_inputbytes() usize

pub fn crypto_core_salsa20_inputbytes() usize {
	return C.crypto_core_salsa20_inputbytes()
}

fn C.crypto_core_salsa20_keybytes() usize

pub fn crypto_core_salsa20_keybytes() usize {
	return C.crypto_core_salsa20_keybytes()
}

fn C.crypto_core_salsa20_constbytes() usize

pub fn crypto_core_salsa20_constbytes() usize {
	return C.crypto_core_salsa20_constbytes()
}

fn C.crypto_core_salsa2012(out &u8, in_ &u8, k &u8, c &u8) int

pub fn crypto_core_salsa2012(out &u8, in_ &u8, k &u8, c &u8) int {
	return C.crypto_core_salsa2012(out, in_, k, c)
}

fn C.crypto_core_salsa2012_outputbytes() usize

pub fn crypto_core_salsa2012_outputbytes() usize {
	return C.crypto_core_salsa2012_outputbytes()
}

fn C.crypto_core_salsa2012_inputbytes() usize

pub fn crypto_core_salsa2012_inputbytes() usize {
	return C.crypto_core_salsa2012_inputbytes()
}

fn C.crypto_core_salsa2012_keybytes() usize

pub fn crypto_core_salsa2012_keybytes() usize {
	return C.crypto_core_salsa2012_keybytes()
}

fn C.crypto_core_salsa2012_constbytes() usize

pub fn crypto_core_salsa2012_constbytes() usize {
	return C.crypto_core_salsa2012_constbytes()
}

fn C.crypto_core_salsa208(out &u8, in_ &u8, k &u8, c &u8) int

pub fn crypto_core_salsa208(out &u8, in_ &u8, k &u8, c &u8) int {
	return C.crypto_core_salsa208(out, in_, k, c)
}

// fn C.crypto_core_salsa208_outputbytes() size_t

// pub fn crypto_core_salsa208_outputbytes() size_t {
//	return C.crypto_core_salsa208_outputbytes()
//}

// fn C.crypto_core_salsa208_inputbytes() size_t

// pub fn crypto_core_salsa208_inputbytes() size_t {
//	return C.crypto_core_salsa208_inputbytes()
//}

// fn C.crypto_core_salsa208_keybytes() size_t

// pub fn crypto_core_salsa208_keybytes() size_t {
//	return C.crypto_core_salsa208_keybytes()
//}

// fn C.crypto_core_salsa208_constbytes() size_t

// pub fn crypto_core_salsa208_constbytes() size_t {
//	return C.crypto_core_salsa208_constbytes()
//}

fn C.crypto_core_hchacha20(out &u8, in_ &u8, k &u8, c &u8) int

pub fn crypto_core_hchacha20(out &u8, in_ &u8, k &u8, c &u8) int {
	return C.crypto_core_hchacha20(out, in_, k, c)
}

fn C.crypto_core_hchacha20_outputbytes() usize

pub fn crypto_core_hchacha20_outputbytes() usize {
	return C.crypto_core_hchacha20_outputbytes()
}

fn C.crypto_core_hchacha20_inputbytes() usize

pub fn crypto_core_hchacha20_inputbytes() usize {
	return C.crypto_core_hchacha20_inputbytes()
}

fn C.crypto_core_hchacha20_keybytes() usize

pub fn crypto_core_hchacha20_keybytes() usize {
	return C.crypto_core_hchacha20_keybytes()
}

fn C.crypto_core_hchacha20_constbytes() usize

pub fn crypto_core_hchacha20_constbytes() usize {
	return C.crypto_core_hchacha20_constbytes()
}

fn C.crypto_core_hsalsa20(out &u8, in_ &u8, k &u8, c &u8) int

pub fn crypto_core_hsalsa20(out &u8, in_ &u8, k &u8, c &u8) int {
	return C.crypto_core_hsalsa20(out, in_, k, c)
}

fn C.crypto_core_ed25519_is_valid_point(p &u8) int

pub fn crypto_core_ed25519_is_valid_point(p &u8) int {
	return C.crypto_core_ed25519_is_valid_point(p)
}

fn C.crypto_core_ed25519_add(r &u8, p &u8, q &u8) int

pub fn crypto_core_ed25519_add(r &u8, p &u8, q &u8) int {
	return C.crypto_core_ed25519_add(r, p, q)
}

fn C.crypto_core_ed25519_sub(r &u8, p &u8, q &u8) int

pub fn crypto_core_ed25519_sub(r &u8, p &u8, q &u8) int {
	return C.crypto_core_ed25519_sub(r, p, q)
}

fn C.crypto_core_ed25519_from_uniform(p &u8, r &u8) int

pub fn crypto_core_ed25519_from_uniform(p &u8, r &u8) int {
	return C.crypto_core_ed25519_from_uniform(p, r)
}

fn C.crypto_core_ed25519_scalar_random(r &u8)

pub fn crypto_core_ed25519_scalar_random(r &u8) {
	C.crypto_core_ed25519_scalar_random(r)
}

fn C.crypto_core_ed25519_scalar_invert(recip &u8, s &u8) int

pub fn crypto_core_ed25519_scalar_invert(recip &u8, s &u8) int {
	return C.crypto_core_ed25519_scalar_invert(recip, s)
}

fn C.crypto_core_ed25519_scalar_negate(neg &u8, s &u8)

pub fn crypto_core_ed25519_scalar_negate(neg &u8, s &u8) {
	C.crypto_core_ed25519_scalar_negate(neg, s)
}

fn C.crypto_core_ed25519_scalar_complement(comp &u8, s &u8)

pub fn crypto_core_ed25519_scalar_complement(comp &u8, s &u8) {
	C.crypto_core_ed25519_scalar_complement(comp, s)
}

fn C.crypto_core_ed25519_scalar_add(z &u8, x &u8, y &u8)

pub fn crypto_core_ed25519_scalar_add(z &u8, x &u8, y &u8) {
	C.crypto_core_ed25519_scalar_add(z, x, y)
}

fn C.crypto_core_ed25519_scalar_sub(z &u8, x &u8, y &u8)

pub fn crypto_core_ed25519_scalar_sub(z &u8, x &u8, y &u8) {
	C.crypto_core_ed25519_scalar_sub(z, x, y)
}

fn C.crypto_core_ed25519_bytes() usize

pub fn crypto_core_ed25519_bytes() usize {
	return C.crypto_core_ed25519_bytes()
}

fn C.crypto_core_ed25519_nonreducedscalarbytes() usize

pub fn crypto_core_ed25519_nonreducedscalarbytes() usize {
	return C.crypto_core_ed25519_nonreducedscalarbytes()
}

fn C.crypto_core_ed25519_uniformbytes() usize

pub fn crypto_core_ed25519_uniformbytes() usize {
	return C.crypto_core_ed25519_uniformbytes()
}

fn C.crypto_core_ed25519_scalarbytes() usize

pub fn crypto_core_ed25519_scalarbytes() usize {
	return C.crypto_core_ed25519_scalarbytes()
}

fn C.crypto_secretbox_keybytes() usize

pub fn crypto_secretbox_keybytes() usize {
	return C.crypto_secretbox_keybytes()
}

fn C.crypto_secretbox_keygen(&u8)

fn C.crypto_kx_seed_keypair(pk &u8, sk &u8, seed &u8) int

fn C.crypto_sign_seed_keypair(pk &u8, sk &u8, seed &u8) int
