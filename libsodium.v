module libsodium

#include <sodium.h>
#flag -lsodium

const ( // empty enum
	blake2b_blockbytes = 0
	blake2b_outbytes = 1
	blake2b_keybytes = 2
	blake2b_saltbytes = 3
	blake2b_personalbytes = 4
)

// struct decl name="blake2b_param_"
// typedef struct
// ['referenced', 'blake2b_param', 'struct blake2b_param_:struct blake2b_param_']
struct blake2b_param { 
	digest_length byte
	key_length byte
	fanout byte
	depth byte
	leaf_length [4]byte
	node_offset [8]byte
	node_depth byte
	inner_length byte
	reserved [14]byte
	salt [16]byte
	personal [16]byte
}
// struct decl name="blake2b_state"
// typedef struct
// ['referenced', 'blake2b_state', 'struct blake2b_state:struct blake2b_state']
struct blake2b_state { 
	h [8]u64
	t [2]u64
	f [2]u64
	buf [256]byte
	buflen size_t
	last_node byte
}
type blake2b_compress_fn = fn (&blake2b_state, & byte) int
fn C.blake2b_compress_ref(S &blake2b_state, block &byte) int

pub fn blake2b_compress_ref(S &blake2b_state, block &byte) int {
	return C.blake2b_compress_ref(S, block)
}


const ( // empty enum
)

// struct decl name="blake2b_param_"
// typedef struct
// ['referenced', 'blake2b_param', 'struct blake2b_param_:struct blake2b_param_']
// struct decl name="blake2b_state"
// typedef struct
// ['referenced', 'blake2b_state', 'struct blake2b_state:struct blake2b_state']

const ( // empty enum
)

// struct decl name="blake2b_param_"
// typedef struct
// ['referenced', 'blake2b_param', 'struct blake2b_param_:struct blake2b_param_']
// struct decl name="blake2b_state"
// typedef struct
// ['referenced', 'blake2b_state', 'struct blake2b_state:struct blake2b_state']

const ( // empty enum
)

// struct decl name="blake2b_param_"
// typedef struct
// ['referenced', 'blake2b_param', 'struct blake2b_param_:struct blake2b_param_']
// struct decl name="blake2b_state"
// typedef struct
// ['referenced', 'blake2b_state', 'struct blake2b_state:struct blake2b_state']

const ( // empty enum
)

// struct decl name="blake2b_param_"
// typedef struct
// ['referenced', 'blake2b_param', 'struct blake2b_param_:struct blake2b_param_']
// struct decl name="blake2b_state"
// typedef struct
// ['referenced', 'blake2b_state', 'struct blake2b_state:struct blake2b_state']
fn C.crypto_generichash_blake2b(out &byte, outlen size_t, in_ &byte, inlen u64, key &byte, keylen size_t) int

pub fn crypto_generichash_blake2b(out &byte, outlen size_t, in_ &byte, inlen u64, key &byte, keylen size_t) int {
	return C.crypto_generichash_blake2b(out, outlen, in_, inlen, key, keylen)
}

fn C.crypto_generichash_blake2b_salt_personal(out &byte, outlen size_t, in_ &byte, inlen u64, key &byte, keylen size_t, salt &byte, personal &byte) int

pub fn crypto_generichash_blake2b_salt_personal(out &byte, outlen size_t, in_ &byte, inlen u64, key &byte, keylen size_t, salt &byte, personal &byte) int {
	return C.crypto_generichash_blake2b_salt_personal(out, outlen, in_, inlen, key, keylen, salt, personal)
}


const ( // empty enum
)

// struct decl name="blake2b_param_"
// typedef struct
// ['referenced', 'blake2b_param', 'struct blake2b_param_:struct blake2b_param_']
// struct decl name="blake2b_state"
// typedef struct
// ['referenced', 'blake2b_state', 'struct blake2b_state:struct blake2b_state']
fn C.blake2b_set_lastnode(S &blake2b_state) int

pub fn blake2b_set_lastnode(S &blake2b_state) int {
	return C.blake2b_set_lastnode(S)
}

fn C.blake2b_is_lastblock(S &blake2b_state) int

pub fn blake2b_is_lastblock(S &blake2b_state) int {
	return C.blake2b_is_lastblock(S)
}

fn C.blake2b_set_lastblock(S &blake2b_state) int

pub fn blake2b_set_lastblock(S &blake2b_state) int {
	return C.blake2b_set_lastblock(S)
}

fn C.blake2b_increment_counter(S &blake2b_state, inc u64) int

pub fn blake2b_increment_counter(S &blake2b_state, inc u64) int {
	return C.blake2b_increment_counter(S, inc)
}

fn C.blake2b_param_set_salt(P &blake2b_param, salt &byte) int

pub fn blake2b_param_set_salt(P &blake2b_param, salt &byte) int {
	return C.blake2b_param_set_salt(P, salt)
}

fn C.blake2b_param_set_personal(P &blake2b_param, personal &byte) int

pub fn blake2b_param_set_personal(P &blake2b_param, personal &byte) int {
	return C.blake2b_param_set_personal(P, personal)
}

fn C.blake2b_init0(S &blake2b_state) int

pub fn blake2b_init0(S &blake2b_state) int {
	return C.blake2b_init0(S)
}

fn C.blake2b_init_param(S &blake2b_state, P &blake2b_param) int

pub fn blake2b_init_param(S &blake2b_state, P &blake2b_param) int {
	return C.blake2b_init_param(S, P)
}

fn C.blake2b_init(S &blake2b_state, outlen byte) int

pub fn blake2b_init(S &blake2b_state, outlen byte) int {
	return C.blake2b_init(S, outlen)
}

fn C.blake2b_init_salt_personal(S &blake2b_state, outlen byte, salt voidptr, personal voidptr) int

pub fn blake2b_init_salt_personal(S &blake2b_state, outlen byte, salt voidptr, personal voidptr) int {
	return C.blake2b_init_salt_personal(S, outlen, salt, personal)
}

fn C.blake2b_init_key(S &blake2b_state, outlen byte, key voidptr, keylen byte) int

pub fn blake2b_init_key(S &blake2b_state, outlen byte, key voidptr, keylen byte) int {
	return C.blake2b_init_key(S, outlen, key, keylen)
}

fn C.blake2b_init_key_salt_personal(S &blake2b_state, outlen byte, key voidptr, keylen byte, salt voidptr, personal voidptr) int

pub fn blake2b_init_key_salt_personal(S &blake2b_state, outlen byte, key voidptr, keylen byte, salt voidptr, personal voidptr) int {
	return C.blake2b_init_key_salt_personal(S, outlen, key, keylen, salt, personal)
}

fn C.blake2b_update(S &blake2b_state, in_ &byte, inlen u64) int

pub fn blake2b_update(S &blake2b_state, in_ &byte, inlen u64) int {
	return C.blake2b_update(S, in_, inlen)
}

fn C.blake2b_final(S &blake2b_state, out &byte, outlen byte) int

pub fn blake2b_final(S &blake2b_state, out &byte, outlen byte) int {
	return C.blake2b_final(S, out, outlen)
}

fn C.blake2b(out &byte, in_ voidptr, key voidptr, outlen byte, inlen u64, keylen byte) int

pub fn blake2b(out &byte, in_ voidptr, key voidptr, outlen byte, inlen u64, keylen byte) int {
	return C.blake2b(out, in_, key, outlen, inlen, keylen)
}

fn C.blake2b_salt_personal(out &byte, in_ voidptr, key voidptr, outlen byte, inlen u64, keylen byte, salt voidptr, personal voidptr) int

pub fn blake2b_salt_personal(out &byte, in_ voidptr, key voidptr, outlen byte, inlen u64, keylen byte, salt voidptr, personal voidptr) int {
	return C.blake2b_salt_personal(out, in_, key, outlen, inlen, keylen, salt, personal)
}

fn C.blake2b_pick_best_implementation() int

pub fn blake2b_pick_best_implementation() int {
	return C.blake2b_pick_best_implementation()
}

fn C.crypto_generichash_primitive() &char

pub fn crypto_generichash_primitive() &char {
	return C.crypto_generichash_primitive()
}

fn C.crypto_kx_publickeybytes() size_t

pub fn crypto_kx_publickeybytes() size_t {
	return C.crypto_kx_publickeybytes()
}

fn C.crypto_kx_secretkeybytes() size_t

pub fn crypto_kx_secretkeybytes() size_t {
	return C.crypto_kx_secretkeybytes()
}

fn C.crypto_kx_seedbytes() size_t

pub fn crypto_kx_seedbytes() size_t {
	return C.crypto_kx_seedbytes()
}

fn C.crypto_kx_sessionkeybytes() size_t

pub fn crypto_kx_sessionkeybytes() size_t {
	return C.crypto_kx_sessionkeybytes()
}

fn C.crypto_kx_primitive() &char

pub fn crypto_kx_primitive() &char {
	return C.crypto_kx_primitive()
}

fn C.crypto_sign_primitive() &char

pub fn crypto_sign_primitive() &char {
	return C.crypto_sign_primitive()
}

fn C.crypto_sign_seed_keypair(pk &byte, sk &byte, seed &byte) int

pub fn crypto_sign_seed_keypair(pk &byte, sk &byte, seed &byte) int {
	return C.crypto_sign_seed_keypair(pk, sk, seed)
}

fn C.crypto_sign_keypair(pk &byte, sk &byte) int

pub fn crypto_sign_keypair(pk &byte, sk &byte) int {
	return C.crypto_sign_keypair(pk, sk)
}

fn C.crypto_sign(sm &byte, smlen_p &u64, m &byte, mlen u64, sk &byte) int

pub fn crypto_sign(sm &byte, smlen_p &u64, m &byte, mlen u64, sk &byte) int {
	return C.crypto_sign(sm, smlen_p, m, mlen, sk)
}

fn C.crypto_sign_open(m &byte, mlen_p &u64, sm &byte, smlen u64, pk &byte) int

pub fn crypto_sign_open(m &byte, mlen_p &u64, sm &byte, smlen u64, pk &byte) int {
	return C.crypto_sign_open(m, mlen_p, sm, smlen, pk)
}

fn C.crypto_sign_detached(sig &byte, siglen_p &u64, m &byte, mlen u64, sk &byte) int

pub fn crypto_sign_detached(sig &byte, siglen_p &u64, m &byte, mlen u64, sk &byte) int {
	return C.crypto_sign_detached(sig, siglen_p, m, mlen, sk)
}

fn C.crypto_sign_verify_detached(sig &byte, m &byte, mlen u64, pk &byte) int

pub fn crypto_sign_verify_detached(sig &byte, m &byte, mlen u64, pk &byte) int {
	return C.crypto_sign_verify_detached(sig, m, mlen, pk)
}

fn C.crypto_sign_ed25519ph_statebytes() size_t

pub fn crypto_sign_ed25519ph_statebytes() size_t {
	return C.crypto_sign_ed25519ph_statebytes()
}

fn C.crypto_sign_ed25519_bytes() size_t

pub fn crypto_sign_ed25519_bytes() size_t {
	return C.crypto_sign_ed25519_bytes()
}

fn C.crypto_sign_ed25519_seedbytes() size_t

pub fn crypto_sign_ed25519_seedbytes() size_t {
	return C.crypto_sign_ed25519_seedbytes()
}

fn C.crypto_sign_ed25519_publickeybytes() size_t

pub fn crypto_sign_ed25519_publickeybytes() size_t {
	return C.crypto_sign_ed25519_publickeybytes()
}

fn C.crypto_sign_ed25519_secretkeybytes() size_t

pub fn crypto_sign_ed25519_secretkeybytes() size_t {
	return C.crypto_sign_ed25519_secretkeybytes()
}

fn C.crypto_sign_ed25519_messagebytes_max() size_t

pub fn crypto_sign_ed25519_messagebytes_max() size_t {
	return C.crypto_sign_ed25519_messagebytes_max()
}

fn C.crypto_sign_ed25519_sk_to_seed(seed &byte, sk &byte) int

pub fn crypto_sign_ed25519_sk_to_seed(seed &byte, sk &byte) int {
	return C.crypto_sign_ed25519_sk_to_seed(seed, sk)
}

fn C.crypto_sign_ed25519_sk_to_pk(pk &byte, sk &byte) int

pub fn crypto_sign_ed25519_sk_to_pk(pk &byte, sk &byte) int {
	return C.crypto_sign_ed25519_sk_to_pk(pk, sk)
}

fn C.crypto_sign_ed25519_detached(sig &byte, siglen_p &u64, m &byte, mlen u64, sk &byte) int

pub fn crypto_sign_ed25519_detached(sig &byte, siglen_p &u64, m &byte, mlen u64, sk &byte) int {
	return C.crypto_sign_ed25519_detached(sig, siglen_p, m, mlen, sk)
}

fn C.crypto_sign_ed25519(sm &byte, smlen_p &u64, m &byte, mlen u64, sk &byte) int

pub fn crypto_sign_ed25519(sm &byte, smlen_p &u64, m &byte, mlen u64, sk &byte) int {
	return C.crypto_sign_ed25519(sm, smlen_p, m, mlen, sk)
}

fn C.crypto_sign_ed25519_seed_keypair(pk &byte, sk &byte, seed &byte) int

pub fn crypto_sign_ed25519_seed_keypair(pk &byte, sk &byte, seed &byte) int {
	return C.crypto_sign_ed25519_seed_keypair(pk, sk, seed)
}

fn C.crypto_sign_ed25519_keypair(pk &byte, sk &byte) int

pub fn crypto_sign_ed25519_keypair(pk &byte, sk &byte) int {
	return C.crypto_sign_ed25519_keypair(pk, sk)
}

fn C.crypto_sign_ed25519_pk_to_curve25519(curve25519_pk &byte, ed25519_pk &byte) int

pub fn crypto_sign_ed25519_pk_to_curve25519(curve25519_pk &byte, ed25519_pk &byte) int {
	return C.crypto_sign_ed25519_pk_to_curve25519(curve25519_pk, ed25519_pk)
}

fn C.crypto_sign_ed25519_sk_to_curve25519(curve25519_sk &byte, ed25519_sk &byte) int

pub fn crypto_sign_ed25519_sk_to_curve25519(curve25519_sk &byte, ed25519_sk &byte) int {
	return C.crypto_sign_ed25519_sk_to_curve25519(curve25519_sk, ed25519_sk)
}

fn C.crypto_sign_ed25519_verify_detached(sig &byte, m &byte, mlen u64, pk &byte) int

pub fn crypto_sign_ed25519_verify_detached(sig &byte, m &byte, mlen u64, pk &byte) int {
	return C.crypto_sign_ed25519_verify_detached(sig, m, mlen, pk)
}

fn C.crypto_sign_ed25519_open(m &byte, mlen_p &u64, sm &byte, smlen u64, pk &byte) int

pub fn crypto_sign_ed25519_open(m &byte, mlen_p &u64, sm &byte, smlen u64, pk &byte) int {
	return C.crypto_sign_ed25519_open(m, mlen_p, sm, smlen, pk)
}

fn C.crypto_secretbox_xsalsa20poly1305(c &byte, m &byte, mlen u64, n &byte, k &byte) int

pub fn crypto_secretbox_xsalsa20poly1305(c &byte, m &byte, mlen u64, n &byte, k &byte) int {
	return C.crypto_secretbox_xsalsa20poly1305(c, m, mlen, n, k)
}

fn C.crypto_secretbox_xsalsa20poly1305_open(m &byte, c &byte, clen u64, n &byte, k &byte) int

pub fn crypto_secretbox_xsalsa20poly1305_open(m &byte, c &byte, clen u64, n &byte, k &byte) int {
	return C.crypto_secretbox_xsalsa20poly1305_open(m, c, clen, n, k)
}

fn C.crypto_secretbox_xchacha20poly1305_detached(c &byte, mac &byte, m &byte, mlen u64, n &byte, k &byte) int

pub fn crypto_secretbox_xchacha20poly1305_detached(c &byte, mac &byte, m &byte, mlen u64, n &byte, k &byte) int {
	return C.crypto_secretbox_xchacha20poly1305_detached(c, mac, m, mlen, n, k)
}

fn C.crypto_secretbox_xchacha20poly1305_easy(c &byte, m &byte, mlen u64, n &byte, k &byte) int

pub fn crypto_secretbox_xchacha20poly1305_easy(c &byte, m &byte, mlen u64, n &byte, k &byte) int {
	return C.crypto_secretbox_xchacha20poly1305_easy(c, m, mlen, n, k)
}

fn C.crypto_secretbox_xchacha20poly1305_open_detached(m &byte, c &byte, mac &byte, clen u64, n &byte, k &byte) int

pub fn crypto_secretbox_xchacha20poly1305_open_detached(m &byte, c &byte, mac &byte, clen u64, n &byte, k &byte) int {
	return C.crypto_secretbox_xchacha20poly1305_open_detached(m, c, mac, clen, n, k)
}

fn C.crypto_secretbox_xchacha20poly1305_open_easy(m &byte, c &byte, clen u64, n &byte, k &byte) int

pub fn crypto_secretbox_xchacha20poly1305_open_easy(m &byte, c &byte, clen u64, n &byte, k &byte) int {
	return C.crypto_secretbox_xchacha20poly1305_open_easy(m, c, clen, n, k)
}

fn C.crypto_secretbox_xchacha20poly1305_keybytes() size_t

pub fn crypto_secretbox_xchacha20poly1305_keybytes() size_t {
	return C.crypto_secretbox_xchacha20poly1305_keybytes()
}

fn C.crypto_secretbox_xchacha20poly1305_noncebytes() size_t

pub fn crypto_secretbox_xchacha20poly1305_noncebytes() size_t {
	return C.crypto_secretbox_xchacha20poly1305_noncebytes()
}

fn C.crypto_secretbox_xchacha20poly1305_macbytes() size_t

pub fn crypto_secretbox_xchacha20poly1305_macbytes() size_t {
	return C.crypto_secretbox_xchacha20poly1305_macbytes()
}

fn C.crypto_secretbox_xchacha20poly1305_messagebytes_max() size_t

pub fn crypto_secretbox_xchacha20poly1305_messagebytes_max() size_t {
	return C.crypto_secretbox_xchacha20poly1305_messagebytes_max()
}

fn C.crypto_secretbox_primitive() &char

pub fn crypto_secretbox_primitive() &char {
	return C.crypto_secretbox_primitive()
}

fn C.crypto_secretbox(c &byte, m &byte, mlen u64, n &byte, k &byte) int

pub fn crypto_secretbox(c &byte, m &byte, mlen u64, n &byte, k &byte) int {
	return C.crypto_secretbox(c, m, mlen, n, k)
}

fn C.crypto_secretbox_open(m &byte, c &byte, clen u64, n &byte, k &byte) int

pub fn crypto_secretbox_open(m &byte, c &byte, clen u64, n &byte, k &byte) int {
	return C.crypto_secretbox_open(m, c, clen, n, k)
}

fn C.crypto_secretbox_detached(c &byte, mac &byte, m &byte, mlen u64, n &byte, k &byte) int

pub fn crypto_secretbox_detached(c &byte, mac &byte, m &byte, mlen u64, n &byte, k &byte) int {
	return C.crypto_secretbox_detached(c, mac, m, mlen, n, k)
}

fn C.crypto_secretbox_easy(c &byte, m &byte, mlen u64, n &byte, k &byte) int

pub fn crypto_secretbox_easy(c &byte, m &byte, mlen u64, n &byte, k &byte) int {
	return C.crypto_secretbox_easy(c, m, mlen, n, k)
}

fn C.crypto_secretbox_open_detached(m &byte, c &byte, mac &byte, clen u64, n &byte, k &byte) int

pub fn crypto_secretbox_open_detached(m &byte, c &byte, mac &byte, clen u64, n &byte, k &byte) int {
	return C.crypto_secretbox_open_detached(m, c, mac, clen, n, k)
}

fn C.crypto_secretbox_open_easy(m &byte, c &byte, clen u64, n &byte, k &byte) int

pub fn crypto_secretbox_open_easy(m &byte, c &byte, clen u64, n &byte, k &byte) int {
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

fn C.crypto_pwhash_bytes_min() size_t

pub fn crypto_pwhash_bytes_min() size_t {
	return C.crypto_pwhash_bytes_min()
}

fn C.crypto_pwhash_bytes_max() size_t

pub fn crypto_pwhash_bytes_max() size_t {
	return C.crypto_pwhash_bytes_max()
}

fn C.crypto_pwhash_passwd_min() size_t

pub fn crypto_pwhash_passwd_min() size_t {
	return C.crypto_pwhash_passwd_min()
}

fn C.crypto_pwhash_passwd_max() size_t

pub fn crypto_pwhash_passwd_max() size_t {
	return C.crypto_pwhash_passwd_max()
}

fn C.crypto_pwhash_saltbytes() size_t

pub fn crypto_pwhash_saltbytes() size_t {
	return C.crypto_pwhash_saltbytes()
}

fn C.crypto_pwhash_strbytes() size_t

pub fn crypto_pwhash_strbytes() size_t {
	return C.crypto_pwhash_strbytes()
}

fn C.crypto_pwhash_strprefix() &char

pub fn crypto_pwhash_strprefix() &char {
	return C.crypto_pwhash_strprefix()
}

fn C.crypto_pwhash_opslimit_min() u64

pub fn crypto_pwhash_opslimit_min() u64 {
	return C.crypto_pwhash_opslimit_min()
}

fn C.crypto_pwhash_opslimit_max() u64

pub fn crypto_pwhash_opslimit_max() u64 {
	return C.crypto_pwhash_opslimit_max()
}

fn C.crypto_pwhash_memlimit_min() size_t

pub fn crypto_pwhash_memlimit_min() size_t {
	return C.crypto_pwhash_memlimit_min()
}

fn C.crypto_pwhash_memlimit_max() size_t

pub fn crypto_pwhash_memlimit_max() size_t {
	return C.crypto_pwhash_memlimit_max()
}

fn C.crypto_pwhash_opslimit_interactive() u64

pub fn crypto_pwhash_opslimit_interactive() u64 {
	return C.crypto_pwhash_opslimit_interactive()
}

fn C.crypto_pwhash_memlimit_interactive() size_t

pub fn crypto_pwhash_memlimit_interactive() size_t {
	return C.crypto_pwhash_memlimit_interactive()
}

fn C.crypto_pwhash_opslimit_moderate() u64

pub fn crypto_pwhash_opslimit_moderate() u64 {
	return C.crypto_pwhash_opslimit_moderate()
}

fn C.crypto_pwhash_memlimit_moderate() size_t

pub fn crypto_pwhash_memlimit_moderate() size_t {
	return C.crypto_pwhash_memlimit_moderate()
}

fn C.crypto_pwhash_opslimit_sensitive() u64

pub fn crypto_pwhash_opslimit_sensitive() u64 {
	return C.crypto_pwhash_opslimit_sensitive()
}

fn C.crypto_pwhash_memlimit_sensitive() size_t

pub fn crypto_pwhash_memlimit_sensitive() size_t {
	return C.crypto_pwhash_memlimit_sensitive()
}

fn C.crypto_pwhash(out &byte, outlen u64, passwd &char, passwdlen u64, salt &byte, opslimit u64, memlimit size_t, alg int) int

pub fn crypto_pwhash(out &byte, outlen u64, passwd &char, passwdlen u64, salt &byte, opslimit u64, memlimit size_t, alg int) int {
	return C.crypto_pwhash(out, outlen, passwd, passwdlen, salt, opslimit, memlimit, alg)
}

fn C.crypto_pwhash_primitive() &char

pub fn crypto_pwhash_primitive() &char {
	return C.crypto_pwhash_primitive()
}

fn C.blake2b_long(pout voidptr, outlen size_t, in_ voidptr, inlen size_t) int

pub fn blake2b_long(pout voidptr, outlen size_t, in_ voidptr, inlen size_t) int {
	return C.blake2b_long(pout, outlen, in_, inlen)
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

// struct decl name="Argon2_Context"
// typedef struct
// ['referenced', 'argon2_context', 'struct Argon2_Context:struct Argon2_Context']
struct argon2_context { 
	out &byte
	outlen u32
	pwd &byte
	pwdlen u32
	salt &byte
	saltlen u32
	secret &byte
	secretlen u32
	ad &byte
	adlen u32
	t_cost u32
	m_cost u32
	lanes u32
	threads u32
	flags u32
}
enum Argon2_type {
	argon2_i
	argon2_id
}


const ( // empty enum
	argon2_version_number = 0
	argon2_block_size = 1
	argon2_qwords_in_block = 2
	argon2_owords_in_block = 3
	argon2_hwords_in_block = 4
	argon2_512bit_words_in_block = 5
	argon2_addresses_in_block = 6
	argon2_prehash_digest_length = 7
	argon2_prehash_seed_length = 8
)

// struct decl name="block_"
// typedef struct
// ['referenced', 'block', 'struct block_:struct block_']
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
fn C.init_block_value(b &block, in_ byte) 

pub fn init_block_value(b &block, in_ byte)  {
	C.init_block_value(b, in_)
}

fn C.copy_block(dst &block, src &block) 

pub fn copy_block(dst &block, src &block)  {
	C.copy_block(dst, src)
}

fn C.xor_block(dst &block, src &block) 

pub fn xor_block(dst &block, src &block)  {
	C.xor_block(dst, src)
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
fn C.index_alpha(instance &argon2_instance_t, position &argon2_position_t, pseudo_rand u32, same_lane int) u32

pub fn index_alpha(instance &argon2_instance_t, position &argon2_position_t, pseudo_rand u32, same_lane int) u32 {
	return C.index_alpha(instance, position, pseudo_rand, same_lane)
}

type fill_segment_fn = fn (&argon2_instance_t, argon2_position_t)
fn C.load_block(dst &block, input voidptr) 

pub fn load_block(dst &block, input voidptr)  {
	C.load_block(dst, input)
}

fn C.store_block(output voidptr, src &block) 

pub fn store_block(output voidptr, src &block)  {
	C.store_block(output, src)
}

fn C.allocate_memory(region &&block_region, m_cost u32) int

pub fn allocate_memory(region &&block_region, m_cost u32) int {
	return C.allocate_memory(region, m_cost)
}

fn C.free_memory(region &block_region) 

pub fn free_memory(region &block_region)  {
	C.free_memory(region)
}

fn C.argon2_free_instance(instance &argon2_instance_t, flags int) 

pub fn argon2_free_instance(instance &argon2_instance_t, flags int)  {
	C.argon2_free_instance(instance, flags)
}

fn C.argon2_finalize(context &argon2_context, instance &argon2_instance_t) 

pub fn argon2_finalize(context &argon2_context, instance &argon2_instance_t)  {
	C.argon2_finalize(context, instance)
}

fn C.argon2_fill_memory_blocks(instance &argon2_instance_t, pass u32) 

pub fn argon2_fill_memory_blocks(instance &argon2_instance_t, pass u32)  {
	C.argon2_fill_memory_blocks(instance, pass)
}

fn C.argon2_validate_inputs(context &argon2_context) int

pub fn argon2_validate_inputs(context &argon2_context) int {
	return C.argon2_validate_inputs(context)
}

fn C.argon2_fill_first_blocks(blockhash &byte, instance &argon2_instance_t) 

pub fn argon2_fill_first_blocks(blockhash &byte, instance &argon2_instance_t)  {
	C.argon2_fill_first_blocks(blockhash, instance)
}

fn C.argon2_initial_hash(blockhash &byte, context &argon2_context, type_ Argon2_type) 

pub fn argon2_initial_hash(blockhash &byte, context &argon2_context, type_ Argon2_type)  {
	C.argon2_initial_hash(blockhash, context, type_)
}

fn C.argon2_initialize(instance &argon2_instance_t, context &argon2_context) int

pub fn argon2_initialize(instance &argon2_instance_t, context &argon2_context) int {
	return C.argon2_initialize(instance, context)
}

fn C.argon2_pick_best_implementation() int

pub fn argon2_pick_best_implementation() int {
	return C.argon2_pick_best_implementation()
}

// struct decl name="Argon2_Context"
// typedef struct
// ['referenced', 'argon2_context', 'struct Argon2_Context:struct Argon2_Context']

const ( // empty enum
)

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

const ( // empty enum
)

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
fn C.fBlaMka(x u64, y u64) u64

pub fn fBlaMka(x u64, y u64) u64 {
	return C.fBlaMka(x, y)
}

fn C.fill_block(prev_block &block, ref_block &block, next_block &block) 

pub fn fill_block(prev_block &block, ref_block &block, next_block &block)  {
	C.fill_block(prev_block, ref_block, next_block)
}

fn C.fill_block_with_xor(prev_block &block, ref_block &block, next_block &block) 

pub fn fill_block_with_xor(prev_block &block, ref_block &block, next_block &block)  {
	C.fill_block_with_xor(prev_block, ref_block, next_block)
}

fn C.generate_addresses(instance &argon2_instance_t, position &argon2_position_t, pseudo_rands &u64) 

pub fn generate_addresses(instance &argon2_instance_t, position &argon2_position_t, pseudo_rands &u64)  {
	C.generate_addresses(instance, position, pseudo_rands)
}

fn C.argon2_fill_segment_ref(instance &argon2_instance_t, position argon2_position_t) 

pub fn argon2_fill_segment_ref(instance &argon2_instance_t, position argon2_position_t)  {
	C.argon2_fill_segment_ref(instance, position)
}

// struct decl name="Argon2_Context"
// typedef struct
// ['referenced', 'argon2_context', 'struct Argon2_Context:struct Argon2_Context']

const ( // empty enum
)

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

const ( // empty enum
)

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

fn C.crypto_pwhash_argon2i_bytes_min() size_t

pub fn crypto_pwhash_argon2i_bytes_min() size_t {
	return C.crypto_pwhash_argon2i_bytes_min()
}

fn C.crypto_pwhash_argon2i_bytes_max() size_t

pub fn crypto_pwhash_argon2i_bytes_max() size_t {
	return C.crypto_pwhash_argon2i_bytes_max()
}

fn C.crypto_pwhash_argon2i_passwd_min() size_t

pub fn crypto_pwhash_argon2i_passwd_min() size_t {
	return C.crypto_pwhash_argon2i_passwd_min()
}

fn C.crypto_pwhash_argon2i_passwd_max() size_t

pub fn crypto_pwhash_argon2i_passwd_max() size_t {
	return C.crypto_pwhash_argon2i_passwd_max()
}

fn C.crypto_pwhash_argon2i_saltbytes() size_t

pub fn crypto_pwhash_argon2i_saltbytes() size_t {
	return C.crypto_pwhash_argon2i_saltbytes()
}

fn C.crypto_pwhash_argon2i_strbytes() size_t

pub fn crypto_pwhash_argon2i_strbytes() size_t {
	return C.crypto_pwhash_argon2i_strbytes()
}

fn C.crypto_pwhash_argon2i_strprefix() &char

pub fn crypto_pwhash_argon2i_strprefix() &char {
	return C.crypto_pwhash_argon2i_strprefix()
}

fn C.crypto_pwhash_argon2i_opslimit_min() u64

pub fn crypto_pwhash_argon2i_opslimit_min() u64 {
	return C.crypto_pwhash_argon2i_opslimit_min()
}

fn C.crypto_pwhash_argon2i_opslimit_max() u64

pub fn crypto_pwhash_argon2i_opslimit_max() u64 {
	return C.crypto_pwhash_argon2i_opslimit_max()
}

fn C.crypto_pwhash_argon2i_memlimit_min() size_t

pub fn crypto_pwhash_argon2i_memlimit_min() size_t {
	return C.crypto_pwhash_argon2i_memlimit_min()
}

fn C.crypto_pwhash_argon2i_memlimit_max() size_t

pub fn crypto_pwhash_argon2i_memlimit_max() size_t {
	return C.crypto_pwhash_argon2i_memlimit_max()
}

fn C.crypto_pwhash_argon2i_opslimit_interactive() u64

pub fn crypto_pwhash_argon2i_opslimit_interactive() u64 {
	return C.crypto_pwhash_argon2i_opslimit_interactive()
}

fn C.crypto_pwhash_argon2i_memlimit_interactive() size_t

pub fn crypto_pwhash_argon2i_memlimit_interactive() size_t {
	return C.crypto_pwhash_argon2i_memlimit_interactive()
}

fn C.crypto_pwhash_argon2i_opslimit_moderate() u64

pub fn crypto_pwhash_argon2i_opslimit_moderate() u64 {
	return C.crypto_pwhash_argon2i_opslimit_moderate()
}

fn C.crypto_pwhash_argon2i_memlimit_moderate() size_t

pub fn crypto_pwhash_argon2i_memlimit_moderate() size_t {
	return C.crypto_pwhash_argon2i_memlimit_moderate()
}

fn C.crypto_pwhash_argon2i_opslimit_sensitive() u64

pub fn crypto_pwhash_argon2i_opslimit_sensitive() u64 {
	return C.crypto_pwhash_argon2i_opslimit_sensitive()
}

fn C.crypto_pwhash_argon2i_memlimit_sensitive() size_t

pub fn crypto_pwhash_argon2i_memlimit_sensitive() size_t {
	return C.crypto_pwhash_argon2i_memlimit_sensitive()
}

fn C.crypto_pwhash_argon2i(out &byte, outlen u64, passwd &char, passwdlen u64, salt &byte, opslimit u64, memlimit size_t, alg int) int

pub fn crypto_pwhash_argon2i(out &byte, outlen u64, passwd &char, passwdlen u64, salt &byte, opslimit u64, memlimit size_t, alg int) int {
	return C.crypto_pwhash_argon2i(out, outlen, passwd, passwdlen, salt, opslimit, memlimit, alg)
}

// struct decl name="Argon2_Context"
// typedef struct
// ['referenced', 'argon2_context', 'struct Argon2_Context:struct Argon2_Context']

const ( // empty enum
)

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

fn C.crypto_pwhash_argon2id_bytes_min() size_t

pub fn crypto_pwhash_argon2id_bytes_min() size_t {
	return C.crypto_pwhash_argon2id_bytes_min()
}

fn C.crypto_pwhash_argon2id_bytes_max() size_t

pub fn crypto_pwhash_argon2id_bytes_max() size_t {
	return C.crypto_pwhash_argon2id_bytes_max()
}

fn C.crypto_pwhash_argon2id_passwd_min() size_t

pub fn crypto_pwhash_argon2id_passwd_min() size_t {
	return C.crypto_pwhash_argon2id_passwd_min()
}

fn C.crypto_pwhash_argon2id_passwd_max() size_t

pub fn crypto_pwhash_argon2id_passwd_max() size_t {
	return C.crypto_pwhash_argon2id_passwd_max()
}

fn C.crypto_pwhash_argon2id_saltbytes() size_t

pub fn crypto_pwhash_argon2id_saltbytes() size_t {
	return C.crypto_pwhash_argon2id_saltbytes()
}

fn C.crypto_pwhash_argon2id_strbytes() size_t

pub fn crypto_pwhash_argon2id_strbytes() size_t {
	return C.crypto_pwhash_argon2id_strbytes()
}

fn C.crypto_pwhash_argon2id_strprefix() &char

pub fn crypto_pwhash_argon2id_strprefix() &char {
	return C.crypto_pwhash_argon2id_strprefix()
}

fn C.crypto_pwhash_argon2id_opslimit_min() u64

pub fn crypto_pwhash_argon2id_opslimit_min() u64 {
	return C.crypto_pwhash_argon2id_opslimit_min()
}

fn C.crypto_pwhash_argon2id_opslimit_max() u64

pub fn crypto_pwhash_argon2id_opslimit_max() u64 {
	return C.crypto_pwhash_argon2id_opslimit_max()
}

fn C.crypto_pwhash_argon2id_memlimit_min() size_t

pub fn crypto_pwhash_argon2id_memlimit_min() size_t {
	return C.crypto_pwhash_argon2id_memlimit_min()
}

fn C.crypto_pwhash_argon2id_memlimit_max() size_t

pub fn crypto_pwhash_argon2id_memlimit_max() size_t {
	return C.crypto_pwhash_argon2id_memlimit_max()
}

fn C.crypto_pwhash_argon2id_opslimit_interactive() u64

pub fn crypto_pwhash_argon2id_opslimit_interactive() u64 {
	return C.crypto_pwhash_argon2id_opslimit_interactive()
}

fn C.crypto_pwhash_argon2id_memlimit_interactive() size_t

pub fn crypto_pwhash_argon2id_memlimit_interactive() size_t {
	return C.crypto_pwhash_argon2id_memlimit_interactive()
}

fn C.crypto_pwhash_argon2id_opslimit_moderate() u64

pub fn crypto_pwhash_argon2id_opslimit_moderate() u64 {
	return C.crypto_pwhash_argon2id_opslimit_moderate()
}

fn C.crypto_pwhash_argon2id_memlimit_moderate() size_t

pub fn crypto_pwhash_argon2id_memlimit_moderate() size_t {
	return C.crypto_pwhash_argon2id_memlimit_moderate()
}

fn C.crypto_pwhash_argon2id_opslimit_sensitive() u64

pub fn crypto_pwhash_argon2id_opslimit_sensitive() u64 {
	return C.crypto_pwhash_argon2id_opslimit_sensitive()
}

fn C.crypto_pwhash_argon2id_memlimit_sensitive() size_t

pub fn crypto_pwhash_argon2id_memlimit_sensitive() size_t {
	return C.crypto_pwhash_argon2id_memlimit_sensitive()
}

fn C.crypto_pwhash_argon2id(out &byte, outlen u64, passwd &char, passwdlen u64, salt &byte, opslimit u64, memlimit size_t, alg int) int

pub fn crypto_pwhash_argon2id(out &byte, outlen u64, passwd &char, passwdlen u64, salt &byte, opslimit u64, memlimit size_t, alg int) int {
	return C.crypto_pwhash_argon2id(out, outlen, passwd, passwdlen, salt, opslimit, memlimit, alg)
}

// struct decl name="Argon2_Context"
// typedef struct
// ['referenced', 'argon2_context', 'struct Argon2_Context:struct Argon2_Context']

const ( // empty enum
)

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
fn C.argon2_ctx(context &argon2_context, type_ Argon2_type) int

pub fn argon2_ctx(context &argon2_context, type_ Argon2_type) int {
	return C.argon2_ctx(context, type_)
}

fn C.argon2_hash(t_cost u32, m_cost u32, parallelism u32, pwd voidptr, pwdlen size_t, salt voidptr, saltlen size_t, hash voidptr, hashlen size_t, encoded &char, encodedlen size_t, type_ Argon2_type) int

pub fn argon2_hash(t_cost u32, m_cost u32, parallelism u32, pwd voidptr, pwdlen size_t, salt voidptr, saltlen size_t, hash voidptr, hashlen size_t, encoded &char, encodedlen size_t, type_ Argon2_type) int {
	return C.argon2_hash(t_cost, m_cost, parallelism, pwd, pwdlen, salt, saltlen, hash, hashlen, encoded, encodedlen, type_)
}

fn C.argon2i_hash_encoded(t_cost u32, m_cost u32, parallelism u32, pwd voidptr, pwdlen size_t, salt voidptr, saltlen size_t, hashlen size_t, encoded &char, encodedlen size_t) int

pub fn argon2i_hash_encoded(t_cost u32, m_cost u32, parallelism u32, pwd voidptr, pwdlen size_t, salt voidptr, saltlen size_t, hashlen size_t, encoded &char, encodedlen size_t) int {
	return C.argon2i_hash_encoded(t_cost, m_cost, parallelism, pwd, pwdlen, salt, saltlen, hashlen, encoded, encodedlen)
}

fn C.argon2i_hash_raw(t_cost u32, m_cost u32, parallelism u32, pwd voidptr, pwdlen size_t, salt voidptr, saltlen size_t, hash voidptr, hashlen size_t) int

pub fn argon2i_hash_raw(t_cost u32, m_cost u32, parallelism u32, pwd voidptr, pwdlen size_t, salt voidptr, saltlen size_t, hash voidptr, hashlen size_t) int {
	return C.argon2i_hash_raw(t_cost, m_cost, parallelism, pwd, pwdlen, salt, saltlen, hash, hashlen)
}

fn C.argon2id_hash_encoded(t_cost u32, m_cost u32, parallelism u32, pwd voidptr, pwdlen size_t, salt voidptr, saltlen size_t, hashlen size_t, encoded &char, encodedlen size_t) int

pub fn argon2id_hash_encoded(t_cost u32, m_cost u32, parallelism u32, pwd voidptr, pwdlen size_t, salt voidptr, saltlen size_t, hashlen size_t, encoded &char, encodedlen size_t) int {
	return C.argon2id_hash_encoded(t_cost, m_cost, parallelism, pwd, pwdlen, salt, saltlen, hashlen, encoded, encodedlen)
}

fn C.argon2id_hash_raw(t_cost u32, m_cost u32, parallelism u32, pwd voidptr, pwdlen size_t, salt voidptr, saltlen size_t, hash voidptr, hashlen size_t) int

pub fn argon2id_hash_raw(t_cost u32, m_cost u32, parallelism u32, pwd voidptr, pwdlen size_t, salt voidptr, saltlen size_t, hash voidptr, hashlen size_t) int {
	return C.argon2id_hash_raw(t_cost, m_cost, parallelism, pwd, pwdlen, salt, saltlen, hash, hashlen)
}

fn C.argon2_verify(encoded &char, pwd voidptr, pwdlen size_t, type_ Argon2_type) int

pub fn argon2_verify(encoded &char, pwd voidptr, pwdlen size_t, type_ Argon2_type) int {
	return C.argon2_verify(encoded, pwd, pwdlen, type_)
}

fn C.argon2i_verify(encoded &char, pwd voidptr, pwdlen size_t) int

pub fn argon2i_verify(encoded &char, pwd voidptr, pwdlen size_t) int {
	return C.argon2i_verify(encoded, pwd, pwdlen)
}

fn C.argon2id_verify(encoded &char, pwd voidptr, pwdlen size_t) int

pub fn argon2id_verify(encoded &char, pwd voidptr, pwdlen size_t) int {
	return C.argon2id_verify(encoded, pwd, pwdlen)
}

// struct decl name="Argon2_Context"
// typedef struct
// ['referenced', 'argon2_context', 'struct Argon2_Context:struct Argon2_Context']

const ( // empty enum
)

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

const ( // empty enum
)

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
fn C.decode_decimal(str &char, v &u32) &char

pub fn decode_decimal(str &char, v &u32) &char {
	return C.decode_decimal(str, v)
}

fn C.argon2_decode_string(ctx &argon2_context, str &char, type_ Argon2_type) int

pub fn argon2_decode_string(ctx &argon2_context, str &char, type_ Argon2_type) int {
	return C.argon2_decode_string(ctx, str, type_)
}

fn C.u32_to_string(str &char, x u32) 

pub fn u32_to_string(str &char, x u32)  {
	C.u32_to_string(str, x)
}

fn C.argon2_encode_string(dst &char, dst_len size_t, ctx &argon2_context, type_ Argon2_type) int

pub fn argon2_encode_string(dst &char, dst_len size_t, ctx &argon2_context, type_ Argon2_type) int {
	return C.argon2_encode_string(dst, dst_len, ctx, type_)
}

// struct decl name="struct"
// typedef struct
// ['referenced', 'escrypt_region_t', 'struct escrypt_region_t:escrypt_region_t']
struct escrypt_region_t { 
	base voidptr
	aligned voidptr
	size size_t
}
type escrypt_local_t = escrypt_region_t
type escrypt_kdf_t = fn (&escrypt_local_t, & byte, size_t, & byte, size_t, u64, u32, u32, & byte, size_t) int
fn C.escrypt_alloc_region(region &escrypt_region_t, size size_t) voidptr

pub fn escrypt_alloc_region(region &escrypt_region_t, size size_t) voidptr {
	return C.escrypt_alloc_region(region, size)
}

fn C.init_region(region &escrypt_region_t) 

pub fn init_region(region &escrypt_region_t)  {
	C.init_region(region)
}

fn C.escrypt_free_region(region &escrypt_region_t) int

pub fn escrypt_free_region(region &escrypt_region_t) int {
	return C.escrypt_free_region(region)
}

fn C.escrypt_init_local(local &escrypt_local_t) int

pub fn escrypt_init_local(local &escrypt_local_t) int {
	return C.escrypt_init_local(local)
}

fn C.escrypt_free_local(local &escrypt_local_t) int

pub fn escrypt_free_local(local &escrypt_local_t) int {
	return C.escrypt_free_local(local)
}

// struct decl name="struct"
// typedef struct
// ['referenced', 'escrypt_region_t', 'struct escrypt_region_t:escrypt_region_t']
fn C.encode64_uint32(dst &byte, dstlen size_t, src u32, srcbits u32) &byte

pub fn encode64_uint32(dst &byte, dstlen size_t, src u32, srcbits u32) &byte {
	return C.encode64_uint32(dst, dstlen, src, srcbits)
}

fn C.encode64(dst &byte, dstlen size_t, src &byte, srclen size_t) &byte

pub fn encode64(dst &byte, dstlen size_t, src &byte, srclen size_t) &byte {
	return C.encode64(dst, dstlen, src, srclen)
}

fn C.decode64_one(dst &u32, src byte) int

pub fn decode64_one(dst &u32, src byte) int {
	return C.decode64_one(dst, src)
}

fn C.decode64_uint32(dst &u32, dstbits u32, src &byte) &byte

pub fn decode64_uint32(dst &u32, dstbits u32, src &byte) &byte {
	return C.decode64_uint32(dst, dstbits, src)
}

fn C.escrypt_parse_setting(setting &byte, N_log2_p &u32, r_p &u32, p_p &u32) &byte

pub fn escrypt_parse_setting(setting &byte, N_log2_p &u32, r_p &u32, p_p &u32) &byte {
	return C.escrypt_parse_setting(setting, N_log2_p, r_p, p_p)
}

fn C.escrypt_r(local &escrypt_local_t, passwd &byte, passwdlen size_t, setting &byte, buf &byte, buflen size_t) &byte

pub fn escrypt_r(local &escrypt_local_t, passwd &byte, passwdlen size_t, setting &byte, buf &byte, buflen size_t) &byte {
	return C.escrypt_r(local, passwd, passwdlen, setting, buf, buflen)
}

fn C.escrypt_gensalt_r(N_log2 u32, r u32, p u32, src &byte, srclen size_t, buf &byte, buflen size_t) &byte

pub fn escrypt_gensalt_r(N_log2 u32, r u32, p u32, src &byte, srclen size_t, buf &byte, buflen size_t) &byte {
	return C.escrypt_gensalt_r(N_log2, r, p, src, srclen, buf, buflen)
}

fn C.crypto_pwhash_scryptsalsa208sha256_ll(passwd &byte, passwdlen size_t, salt &byte, saltlen size_t, N u64, r u32, p u32, buf &byte, buflen size_t) int

pub fn crypto_pwhash_scryptsalsa208sha256_ll(passwd &byte, passwdlen size_t, salt &byte, saltlen size_t, N u64, r u32, p u32, buf &byte, buflen size_t) int {
	return C.crypto_pwhash_scryptsalsa208sha256_ll(passwd, passwdlen, salt, saltlen, N, r, p, buf, buflen)
}

// struct decl name="struct"
// typedef struct
// ['referenced', 'escrypt_region_t', 'struct escrypt_region_t:escrypt_region_t']
fn C.blkcpy(dest &u32, src &u32, len size_t) 

pub fn blkcpy(dest &u32, src &u32, len size_t)  {
	C.blkcpy(dest, src, len)
}

// struct decl name="escrypt_block_t"
// typedef struct
// ['referenced', 'escrypt_block_t', 'union escrypt_block_t:union escrypt_block_t']
struct escrypt_block_t { 
	w [16]u32
	q [8]u64
}
fn C.blkxor(dest &u32, src &u32, len size_t) 

pub fn blkxor(dest &u32, src &u32, len size_t)  {
	C.blkxor(dest, src, len)
}

fn C.salsa20_8(B &u32) 

pub fn salsa20_8(B &u32)  {
	C.salsa20_8(B)
}

fn C.blockmix_salsa8(Bin &u32, Bout &u32, X &u32, r size_t) 

pub fn blockmix_salsa8(Bin &u32, Bout &u32, X &u32, r size_t)  {
	C.blockmix_salsa8(Bin, Bout, X, r)
}

fn C.integerify(B voidptr, r size_t) u64

pub fn integerify(B voidptr, r size_t) u64 {
	return C.integerify(B, r)
}

fn C.smix(B &byte, r size_t, N u64, V &u32, XY &u32) 

pub fn smix(B &byte, r size_t, N u64, V &u32, XY &u32)  {
	C.smix(B, r, N, V, XY)
}

fn C.escrypt_kdf_nosse(local &escrypt_local_t, passwd &byte, passwdlen size_t, salt &byte, saltlen size_t, N u64, _r u32, _p u32, buf &byte, buflen size_t) int

pub fn escrypt_kdf_nosse(local &escrypt_local_t, passwd &byte, passwdlen size_t, salt &byte, saltlen size_t, N u64, _r u32, _p u32, buf &byte, buflen size_t) int {
	return C.escrypt_kdf_nosse(local, passwd, passwdlen, salt, saltlen, N, _r, _p, buf, buflen)
}

// struct decl name="struct"
// typedef struct
// ['referenced', 'escrypt_region_t', 'struct escrypt_region_t:escrypt_region_t']
fn C.pickparams(opslimit u64, memlimit size_t, N_log2 &u32, p &u32, r &u32) int

pub fn pickparams(opslimit u64, memlimit size_t, N_log2 &u32, p &u32, r &u32) int {
	return C.pickparams(opslimit, memlimit, N_log2, p, r)
}

fn C.sodium_strnlen(str &char, maxlen size_t) size_t

pub fn sodium_strnlen(str &char, maxlen size_t) size_t {
	return C.sodium_strnlen(str, maxlen)
}

fn C.crypto_pwhash_scryptsalsa208sha256_bytes_min() size_t

pub fn crypto_pwhash_scryptsalsa208sha256_bytes_min() size_t {
	return C.crypto_pwhash_scryptsalsa208sha256_bytes_min()
}

fn C.crypto_pwhash_scryptsalsa208sha256_bytes_max() size_t

pub fn crypto_pwhash_scryptsalsa208sha256_bytes_max() size_t {
	return C.crypto_pwhash_scryptsalsa208sha256_bytes_max()
}

fn C.crypto_pwhash_scryptsalsa208sha256_passwd_min() size_t

pub fn crypto_pwhash_scryptsalsa208sha256_passwd_min() size_t {
	return C.crypto_pwhash_scryptsalsa208sha256_passwd_min()
}

fn C.crypto_pwhash_scryptsalsa208sha256_passwd_max() size_t

pub fn crypto_pwhash_scryptsalsa208sha256_passwd_max() size_t {
	return C.crypto_pwhash_scryptsalsa208sha256_passwd_max()
}

fn C.crypto_pwhash_scryptsalsa208sha256_saltbytes() size_t

pub fn crypto_pwhash_scryptsalsa208sha256_saltbytes() size_t {
	return C.crypto_pwhash_scryptsalsa208sha256_saltbytes()
}

fn C.crypto_pwhash_scryptsalsa208sha256_strbytes() size_t

pub fn crypto_pwhash_scryptsalsa208sha256_strbytes() size_t {
	return C.crypto_pwhash_scryptsalsa208sha256_strbytes()
}

fn C.crypto_pwhash_scryptsalsa208sha256_strprefix() &char

pub fn crypto_pwhash_scryptsalsa208sha256_strprefix() &char {
	return C.crypto_pwhash_scryptsalsa208sha256_strprefix()
}

fn C.crypto_pwhash_scryptsalsa208sha256_opslimit_min() u64

pub fn crypto_pwhash_scryptsalsa208sha256_opslimit_min() u64 {
	return C.crypto_pwhash_scryptsalsa208sha256_opslimit_min()
}

fn C.crypto_pwhash_scryptsalsa208sha256_opslimit_max() u64

pub fn crypto_pwhash_scryptsalsa208sha256_opslimit_max() u64 {
	return C.crypto_pwhash_scryptsalsa208sha256_opslimit_max()
}

fn C.crypto_pwhash_scryptsalsa208sha256_memlimit_min() size_t

pub fn crypto_pwhash_scryptsalsa208sha256_memlimit_min() size_t {
	return C.crypto_pwhash_scryptsalsa208sha256_memlimit_min()
}

fn C.crypto_pwhash_scryptsalsa208sha256_memlimit_max() size_t

pub fn crypto_pwhash_scryptsalsa208sha256_memlimit_max() size_t {
	return C.crypto_pwhash_scryptsalsa208sha256_memlimit_max()
}

fn C.crypto_pwhash_scryptsalsa208sha256_opslimit_interactive() u64

pub fn crypto_pwhash_scryptsalsa208sha256_opslimit_interactive() u64 {
	return C.crypto_pwhash_scryptsalsa208sha256_opslimit_interactive()
}

fn C.crypto_pwhash_scryptsalsa208sha256_memlimit_interactive() size_t

pub fn crypto_pwhash_scryptsalsa208sha256_memlimit_interactive() size_t {
	return C.crypto_pwhash_scryptsalsa208sha256_memlimit_interactive()
}

fn C.crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive() u64

pub fn crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive() u64 {
	return C.crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive()
}

fn C.crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive() size_t

pub fn crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive() size_t {
	return C.crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive()
}

fn C.crypto_pwhash_scryptsalsa208sha256(out &byte, outlen u64, passwd &char, passwdlen u64, salt &byte, opslimit u64, memlimit size_t) int

pub fn crypto_pwhash_scryptsalsa208sha256(out &byte, outlen u64, passwd &char, passwdlen u64, salt &byte, opslimit u64, memlimit size_t) int {
	return C.crypto_pwhash_scryptsalsa208sha256(out, outlen, passwd, passwdlen, salt, opslimit, memlimit)
}

fn C.escrypt_PBKDF2_SHA256(passwd &byte, passwdlen size_t, salt &byte, saltlen size_t, c u64, buf &byte, dkLen size_t) 

pub fn escrypt_PBKDF2_SHA256(passwd &byte, passwdlen size_t, salt &byte, saltlen size_t, c u64, buf &byte, dkLen size_t)  {
	C.escrypt_PBKDF2_SHA256(passwd, passwdlen, salt, saltlen, c, buf, dkLen)
}

fn C.crypto_verify_16_bytes() size_t

pub fn crypto_verify_16_bytes() size_t {
	return C.crypto_verify_16_bytes()
}

fn C.crypto_verify_32_bytes() size_t

pub fn crypto_verify_32_bytes() size_t {
	return C.crypto_verify_32_bytes()
}

fn C.crypto_verify_64_bytes() size_t

pub fn crypto_verify_64_bytes() size_t {
	return C.crypto_verify_64_bytes()
}

fn C.crypto_verify_n(x_ &byte, y_ &byte, n int) int

pub fn crypto_verify_n(x_ &byte, y_ &byte, n int) int {
	return C.crypto_verify_n(x_, y_, n)
}

fn C.crypto_verify_16(x &byte, y &byte) int

pub fn crypto_verify_16(x &byte, y &byte) int {
	return C.crypto_verify_16(x, y)
}

fn C.crypto_verify_32(x &byte, y &byte) int

pub fn crypto_verify_32(x &byte, y &byte) int {
	return C.crypto_verify_32(x, y)
}

fn C.crypto_verify_64(x &byte, y &byte) int

pub fn crypto_verify_64(x &byte, y &byte) int {
	return C.crypto_verify_64(x, y)
}

fn C.crypto_auth_hmacsha512_bytes() size_t

pub fn crypto_auth_hmacsha512_bytes() size_t {
	return C.crypto_auth_hmacsha512_bytes()
}

fn C.crypto_auth_hmacsha512_keybytes() size_t

pub fn crypto_auth_hmacsha512_keybytes() size_t {
	return C.crypto_auth_hmacsha512_keybytes()
}

fn C.crypto_auth_hmacsha512_statebytes() size_t

pub fn crypto_auth_hmacsha512_statebytes() size_t {
	return C.crypto_auth_hmacsha512_statebytes()
}

fn C.crypto_auth_hmacsha512(out &byte, in_ &byte, inlen u64, k &byte) int

pub fn crypto_auth_hmacsha512(out &byte, in_ &byte, inlen u64, k &byte) int {
	return C.crypto_auth_hmacsha512(out, in_, inlen, k)
}

fn C.crypto_auth_hmacsha512_verify(h &byte, in_ &byte, inlen u64, k &byte) int

pub fn crypto_auth_hmacsha512_verify(h &byte, in_ &byte, inlen u64, k &byte) int {
	return C.crypto_auth_hmacsha512_verify(h, in_, inlen, k)
}

fn C.crypto_auth_hmacsha512256_bytes() size_t

pub fn crypto_auth_hmacsha512256_bytes() size_t {
	return C.crypto_auth_hmacsha512256_bytes()
}

fn C.crypto_auth_hmacsha512256_keybytes() size_t

pub fn crypto_auth_hmacsha512256_keybytes() size_t {
	return C.crypto_auth_hmacsha512256_keybytes()
}

fn C.crypto_auth_hmacsha512256_statebytes() size_t

pub fn crypto_auth_hmacsha512256_statebytes() size_t {
	return C.crypto_auth_hmacsha512256_statebytes()
}

fn C.crypto_auth_hmacsha512256(out &byte, in_ &byte, inlen u64, k &byte) int

pub fn crypto_auth_hmacsha512256(out &byte, in_ &byte, inlen u64, k &byte) int {
	return C.crypto_auth_hmacsha512256(out, in_, inlen, k)
}

fn C.crypto_auth_hmacsha512256_verify(h &byte, in_ &byte, inlen u64, k &byte) int

pub fn crypto_auth_hmacsha512256_verify(h &byte, in_ &byte, inlen u64, k &byte) int {
	return C.crypto_auth_hmacsha512256_verify(h, in_, inlen, k)
}

fn C.crypto_auth_primitive() &char

pub fn crypto_auth_primitive() &char {
	return C.crypto_auth_primitive()
}

fn C.crypto_auth(out &byte, in_ &byte, inlen u64, k &byte) int

pub fn crypto_auth(out &byte, in_ &byte, inlen u64, k &byte) int {
	return C.crypto_auth(out, in_, inlen, k)
}

fn C.crypto_auth_verify(h &byte, in_ &byte, inlen u64, k &byte) int

pub fn crypto_auth_verify(h &byte, in_ &byte, inlen u64, k &byte) int {
	return C.crypto_auth_verify(h, in_, inlen, k)
}

fn C.crypto_auth_hmacsha256_bytes() size_t

pub fn crypto_auth_hmacsha256_bytes() size_t {
	return C.crypto_auth_hmacsha256_bytes()
}

fn C.crypto_auth_hmacsha256_keybytes() size_t

pub fn crypto_auth_hmacsha256_keybytes() size_t {
	return C.crypto_auth_hmacsha256_keybytes()
}

fn C.crypto_auth_hmacsha256_statebytes() size_t

pub fn crypto_auth_hmacsha256_statebytes() size_t {
	return C.crypto_auth_hmacsha256_statebytes()
}

fn C.crypto_auth_hmacsha256(out &byte, in_ &byte, inlen u64, k &byte) int

pub fn crypto_auth_hmacsha256(out &byte, in_ &byte, inlen u64, k &byte) int {
	return C.crypto_auth_hmacsha256(out, in_, inlen, k)
}

fn C.crypto_auth_hmacsha256_verify(h &byte, in_ &byte, inlen u64, k &byte) int

pub fn crypto_auth_hmacsha256_verify(h &byte, in_ &byte, inlen u64, k &byte) int {
	return C.crypto_auth_hmacsha256_verify(h, in_, inlen, k)
}

fn C.crypto_kdf_hkdf_sha256_keybytes() size_t

pub fn crypto_kdf_hkdf_sha256_keybytes() size_t {
	return C.crypto_kdf_hkdf_sha256_keybytes()
}

fn C.crypto_kdf_hkdf_sha256_bytes_min() size_t

pub fn crypto_kdf_hkdf_sha256_bytes_min() size_t {
	return C.crypto_kdf_hkdf_sha256_bytes_min()
}

fn C.crypto_kdf_hkdf_sha256_bytes_max() size_t

pub fn crypto_kdf_hkdf_sha256_bytes_max() size_t {
	return C.crypto_kdf_hkdf_sha256_bytes_max()
}

fn C.crypto_kdf_hkdf_sha512_keybytes() size_t

pub fn crypto_kdf_hkdf_sha512_keybytes() size_t {
	return C.crypto_kdf_hkdf_sha512_keybytes()
}

fn C.crypto_kdf_hkdf_sha512_bytes_min() size_t

pub fn crypto_kdf_hkdf_sha512_bytes_min() size_t {
	return C.crypto_kdf_hkdf_sha512_bytes_min()
}

fn C.crypto_kdf_hkdf_sha512_bytes_max() size_t

pub fn crypto_kdf_hkdf_sha512_bytes_max() size_t {
	return C.crypto_kdf_hkdf_sha512_bytes_max()
}

fn C.crypto_kdf_primitive() &char

pub fn crypto_kdf_primitive() &char {
	return C.crypto_kdf_primitive()
}

fn C.crypto_shorthash_primitive() &char

pub fn crypto_shorthash_primitive() &char {
	return C.crypto_shorthash_primitive()
}

fn C.crypto_shorthash(out &byte, in_ &byte, inlen u64, k &byte) int

pub fn crypto_shorthash(out &byte, in_ &byte, inlen u64, k &byte) int {
	return C.crypto_shorthash(out, in_, inlen, k)
}

fn C.crypto_shorthash_siphashx24(out &byte, in_ &byte, inlen u64, k &byte) int

pub fn crypto_shorthash_siphashx24(out &byte, in_ &byte, inlen u64, k &byte) int {
	return C.crypto_shorthash_siphashx24(out, in_, inlen, k)
}

fn C.crypto_shorthash_siphash24(out &byte, in_ &byte, inlen u64, k &byte) int

pub fn crypto_shorthash_siphash24(out &byte, in_ &byte, inlen u64, k &byte) int {
	return C.crypto_shorthash_siphash24(out, in_, inlen, k)
}

fn C.crypto_scalarmult_base(q &byte, n &byte) int

pub fn crypto_scalarmult_base(q &byte, n &byte) int {
	return C.crypto_scalarmult_base(q, n)
}

fn C.crypto_scalarmult(q &byte, n &byte, p &byte) int

pub fn crypto_scalarmult(q &byte, n &byte, p &byte) int {
	return C.crypto_scalarmult(q, n, p)
}

fn C.crypto_scalarmult_ristretto255(q &byte, n &byte, p &byte) int

pub fn crypto_scalarmult_ristretto255(q &byte, n &byte, p &byte) int {
	return C.crypto_scalarmult_ristretto255(q, n, p)
}

fn C.crypto_scalarmult_ristretto255_base(q &byte, n &byte) int

pub fn crypto_scalarmult_ristretto255_base(q &byte, n &byte) int {
	return C.crypto_scalarmult_ristretto255_base(q, n)
}

fn C.crypto_scalarmult_ristretto255_bytes() size_t

pub fn crypto_scalarmult_ristretto255_bytes() size_t {
	return C.crypto_scalarmult_ristretto255_bytes()
}

fn C.crypto_scalarmult_ristretto255_scalarbytes() size_t

pub fn crypto_scalarmult_ristretto255_scalarbytes() size_t {
	return C.crypto_scalarmult_ristretto255_scalarbytes()
}

fn C.crypto_scalarmult_ed25519(q &byte, n &byte, p &byte) int

pub fn crypto_scalarmult_ed25519(q &byte, n &byte, p &byte) int {
	return C.crypto_scalarmult_ed25519(q, n, p)
}

fn C.crypto_scalarmult_ed25519_noclamp(q &byte, n &byte, p &byte) int

pub fn crypto_scalarmult_ed25519_noclamp(q &byte, n &byte, p &byte) int {
	return C.crypto_scalarmult_ed25519_noclamp(q, n, p)
}

fn C.crypto_scalarmult_ed25519_base(q &byte, n &byte) int

pub fn crypto_scalarmult_ed25519_base(q &byte, n &byte) int {
	return C.crypto_scalarmult_ed25519_base(q, n)
}

fn C.crypto_scalarmult_ed25519_base_noclamp(q &byte, n &byte) int

pub fn crypto_scalarmult_ed25519_base_noclamp(q &byte, n &byte) int {
	return C.crypto_scalarmult_ed25519_base_noclamp(q, n)
}

fn C.crypto_scalarmult_ed25519_bytes() size_t

pub fn crypto_scalarmult_ed25519_bytes() size_t {
	return C.crypto_scalarmult_ed25519_bytes()
}

fn C.crypto_scalarmult_ed25519_scalarbytes() size_t

pub fn crypto_scalarmult_ed25519_scalarbytes() size_t {
	return C.crypto_scalarmult_ed25519_scalarbytes()
}

//type fe = [10]u64
// struct decl name="struct"
// typedef struct
// ['referenced', '_sodium_scalarmult_curve25519_sandy2x_fe51', 'struct _sodium_scalarmult_curve25519_sandy2x_fe51:_sodium_scalarmult_curve25519_sandy2x_fe51']
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
fn C.crypto_scalarmult_curve25519(q &byte, n &byte, p &byte) int

pub fn crypto_scalarmult_curve25519(q &byte, n &byte, p &byte) int {
	return C.crypto_scalarmult_curve25519(q, n, p)
}

fn C.crypto_scalarmult_curve25519_base(q &byte, n &byte) int

pub fn crypto_scalarmult_curve25519_base(q &byte, n &byte) int {
	return C.crypto_scalarmult_curve25519_base(q, n)
}

// struct decl name="crypto_scalarmult_curve25519_implementation"
// typedef struct
// ['crypto_scalarmult_curve25519_implementation', 'struct crypto_scalarmult_curve25519_implementation:struct crypto_scalarmult_curve25519_implementation']
fn C.has_small_order(s &byte) int

pub fn has_small_order(s &byte) int {
	return C.has_small_order(s)
}

fn C.crypto_scalarmult_curve25519_ref10(q &byte, n &byte, p &byte) int

pub fn crypto_scalarmult_curve25519_ref10(q &byte, n &byte, p &byte) int {
	return C.crypto_scalarmult_curve25519_ref10(q, n, p)
}

fn C.crypto_scalarmult_curve25519_ref10_base(q &byte, n &byte) int

pub fn crypto_scalarmult_curve25519_ref10_base(q &byte, n &byte) int {
	return C.crypto_scalarmult_curve25519_ref10_base(q, n)
}

fn C.crypto_onetimeauth(out &byte, in_ &byte, inlen u64, k &byte) int

pub fn crypto_onetimeauth(out &byte, in_ &byte, inlen u64, k &byte) int {
	return C.crypto_onetimeauth(out, in_, inlen, k)
}

fn C.crypto_onetimeauth_verify(h &byte, in_ &byte, inlen u64, k &byte) int

pub fn crypto_onetimeauth_verify(h &byte, in_ &byte, inlen u64, k &byte) int {
	return C.crypto_onetimeauth_verify(h, in_, inlen, k)
}

fn C.crypto_onetimeauth_primitive() &char

pub fn crypto_onetimeauth_primitive() &char {
	return C.crypto_onetimeauth_primitive()
}

// struct decl name="crypto_onetimeauth_poly1305_implementation"
// typedef struct
// ['crypto_onetimeauth_poly1305_implementation', 'struct crypto_onetimeauth_poly1305_implementation:struct crypto_onetimeauth_poly1305_implementation']
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
	buffer [16]byte
	final byte
}
fn C.poly1305_init(st &poly1305_state_internal_t, key &byte) 

pub fn poly1305_init(st &poly1305_state_internal_t, key &byte)  {
	C.poly1305_init(st, key)
}

fn C.poly1305_blocks(st &poly1305_state_internal_t, m &byte, bytes u64) 

pub fn poly1305_blocks(st &poly1305_state_internal_t, m &byte, bytes u64)  {
	C.poly1305_blocks(st, m, bytes)
}

fn C.poly1305_finish(st &poly1305_state_internal_t, mac &byte) 

pub fn poly1305_finish(st &poly1305_state_internal_t, mac &byte)  {
	C.poly1305_finish(st, mac)
}

fn C.poly1305_update(st &poly1305_state_internal_t, m &byte, bytes u64) 

pub fn poly1305_update(st &poly1305_state_internal_t, m &byte, bytes u64)  {
	C.poly1305_update(st, m, bytes)
}

fn C.crypto_onetimeauth_poly1305_donna(out &byte, m &byte, inlen u64, key &byte) int

pub fn crypto_onetimeauth_poly1305_donna(out &byte, m &byte, inlen u64, key &byte) int {
	return C.crypto_onetimeauth_poly1305_donna(out, m, inlen, key)
}

fn C.crypto_onetimeauth_poly1305_donna_verify(h &byte, in_ &byte, inlen u64, k &byte) int

pub fn crypto_onetimeauth_poly1305_donna_verify(h &byte, in_ &byte, inlen u64, k &byte) int {
	return C.crypto_onetimeauth_poly1305_donna_verify(h, in_, inlen, k)
}

// struct decl name="crypto_onetimeauth_poly1305_implementation"
// typedef struct
// ['crypto_onetimeauth_poly1305_implementation', 'struct crypto_onetimeauth_poly1305_implementation:struct crypto_onetimeauth_poly1305_implementation']
// struct decl name="crypto_onetimeauth_poly1305_implementation"
// typedef struct
// ['referenced', 'crypto_onetimeauth_poly1305_implementation', 'struct crypto_onetimeauth_poly1305_implementation:struct crypto_onetimeauth_poly1305_implementation']
fn C.crypto_onetimeauth_poly1305(out &byte, in_ &byte, inlen u64, k &byte) int

pub fn crypto_onetimeauth_poly1305(out &byte, in_ &byte, inlen u64, k &byte) int {
	return C.crypto_onetimeauth_poly1305(out, in_, inlen, k)
}

fn C.crypto_onetimeauth_poly1305_verify(h &byte, in_ &byte, inlen u64, k &byte) int

pub fn crypto_onetimeauth_poly1305_verify(h &byte, in_ &byte, inlen u64, k &byte) int {
	return C.crypto_onetimeauth_poly1305_verify(h, in_, inlen, k)
}

fn C.crypto_onetimeauth_poly1305_bytes() size_t

pub fn crypto_onetimeauth_poly1305_bytes() size_t {
	return C.crypto_onetimeauth_poly1305_bytes()
}

fn C.crypto_onetimeauth_poly1305_keybytes() size_t

pub fn crypto_onetimeauth_poly1305_keybytes() size_t {
	return C.crypto_onetimeauth_poly1305_keybytes()
}

fn C.crypto_onetimeauth_poly1305_statebytes() size_t

pub fn crypto_onetimeauth_poly1305_statebytes() size_t {
	return C.crypto_onetimeauth_poly1305_statebytes()
}

// struct decl name="SysRandom_"
// typedef struct
// ['referenced', 'SysRandom', 'struct SysRandom_:struct SysRandom_']
struct SysRandom { 
	random_data_source_fd int
	initialized int
	getrandom_available int
}
fn C.safe_read(fd int, buf_ voidptr, size size_t) int

pub fn safe_read(fd int, buf_ voidptr, size size_t) int {
	return C.safe_read(fd, buf_, size)
}

fn C.randombytes_sysrandom_random_dev_open() int

pub fn randombytes_sysrandom_random_dev_open() int {
	return C.randombytes_sysrandom_random_dev_open()
}

fn C.randombytes_sysrandom_init() 

pub fn randombytes_sysrandom_init()  {
	C.randombytes_sysrandom_init()
}

fn C.randombytes_sysrandom_stir() 

pub fn randombytes_sysrandom_stir()  {
	C.randombytes_sysrandom_stir()
}

fn C.randombytes_sysrandom_stir_if_needed() 

pub fn randombytes_sysrandom_stir_if_needed()  {
	C.randombytes_sysrandom_stir_if_needed()
}

fn C.randombytes_sysrandom_close() int

pub fn randombytes_sysrandom_close() int {
	return C.randombytes_sysrandom_close()
}

fn C.randombytes_sysrandom_buf(buf voidptr, size size_t) 

pub fn randombytes_sysrandom_buf(buf voidptr, size size_t)  {
	C.randombytes_sysrandom_buf(buf, size)
}

fn C.randombytes_sysrandom() u32

pub fn randombytes_sysrandom() u32 {
	return C.randombytes_sysrandom()
}

fn C.randombytes_sysrandom_implementation_name() &char

pub fn randombytes_sysrandom_implementation_name() &char {
	return C.randombytes_sysrandom_implementation_name()
}

// struct decl name="InternalRandomGlobal_"
// typedef struct
// ['referenced', 'InternalRandomGlobal', 'struct InternalRandomGlobal_:struct InternalRandomGlobal_']
struct InternalRandomGlobal { 
	initialized int
	random_data_source_fd int
	getentropy_available int
	getrandom_available int
	rdrand_available int
}
// struct decl name="InternalRandom_"
// typedef struct
// ['referenced', 'InternalRandom', 'struct InternalRandom_:struct InternalRandom_']
struct InternalRandom { 
	initialized int
	rnd32_outleft size_t
	key byte
	rnd32 byte
	nonce u64
}
fn C.sodium_hrtime() u64

pub fn sodium_hrtime() u64 {
	return C.sodium_hrtime()
}

fn C.randombytes_internal_random_random_dev_open() int

pub fn randombytes_internal_random_random_dev_open() int {
	return C.randombytes_internal_random_random_dev_open()
}

fn C.randombytes_internal_random_init() 

pub fn randombytes_internal_random_init()  {
	C.randombytes_internal_random_init()
}

fn C.randombytes_internal_random_stir() 

pub fn randombytes_internal_random_stir()  {
	C.randombytes_internal_random_stir()
}

fn C.randombytes_internal_random_stir_if_needed() 

pub fn randombytes_internal_random_stir_if_needed()  {
	C.randombytes_internal_random_stir_if_needed()
}

fn C.randombytes_internal_random_close() int

pub fn randombytes_internal_random_close() int {
	return C.randombytes_internal_random_close()
}

fn C.randombytes_internal_random_xorhwrand() 

pub fn randombytes_internal_random_xorhwrand()  {
	C.randombytes_internal_random_xorhwrand()
}

fn C.randombytes_internal_random_xorkey(mix &byte) 

pub fn randombytes_internal_random_xorkey(mix &byte)  {
	C.randombytes_internal_random_xorkey(mix)
}

fn C.randombytes_internal_random_buf(buf voidptr, size size_t) 

pub fn randombytes_internal_random_buf(buf voidptr, size size_t)  {
	C.randombytes_internal_random_buf(buf, size)
}

fn C.randombytes_internal_random() u32

pub fn randombytes_internal_random() u32 {
	return C.randombytes_internal_random()
}

fn C.randombytes_internal_implementation_name() &char

pub fn randombytes_internal_implementation_name() &char {
	return C.randombytes_internal_implementation_name()
}

fn C.randombytes_init_if_needed() 

pub fn randombytes_init_if_needed()  {
	C.randombytes_init_if_needed()
}

fn C.randombytes_implementation_name() &char

pub fn randombytes_implementation_name() &char {
	return C.randombytes_implementation_name()
}

fn C.randombytes_random() u32

pub fn randombytes_random() u32 {
	return C.randombytes_random()
}

fn C.randombytes_uniform(upper_bound u32) u32

pub fn randombytes_uniform(upper_bound u32) u32 {
	return C.randombytes_uniform(upper_bound)
}

fn C.randombytes_buf(buf voidptr, size size_t) 

pub fn randombytes_buf(buf voidptr, size size_t)  {
	C.randombytes_buf(buf, size)
}

fn C.randombytes_seedbytes() size_t

pub fn randombytes_seedbytes() size_t {
	return C.randombytes_seedbytes()
}

fn C.randombytes_close() int

pub fn randombytes_close() int {
	return C.randombytes_close()
}

fn C.randombytes(buf &byte, buf_len u64) 

pub fn randombytes(buf &byte, buf_len u64)  {
	C.randombytes(buf, buf_len)
}

fn C.crypto_box_detached_afternm(c &byte, mac &byte, m &byte, mlen u64, n &byte, k &byte) int

pub fn crypto_box_detached_afternm(c &byte, mac &byte, m &byte, mlen u64, n &byte, k &byte) int {
	return C.crypto_box_detached_afternm(c, mac, m, mlen, n, k)
}

fn C.crypto_box_detached(c &byte, mac &byte, m &byte, mlen u64, n &byte, pk &byte, sk &byte) int

pub fn crypto_box_detached(c &byte, mac &byte, m &byte, mlen u64, n &byte, pk &byte, sk &byte) int {
	return C.crypto_box_detached(c, mac, m, mlen, n, pk, sk)
}

fn C.crypto_box_easy_afternm(c &byte, m &byte, mlen u64, n &byte, k &byte) int

pub fn crypto_box_easy_afternm(c &byte, m &byte, mlen u64, n &byte, k &byte) int {
	return C.crypto_box_easy_afternm(c, m, mlen, n, k)
}

fn C.crypto_box_easy(c &byte, m &byte, mlen u64, n &byte, pk &byte, sk &byte) int

pub fn crypto_box_easy(c &byte, m &byte, mlen u64, n &byte, pk &byte, sk &byte) int {
	return C.crypto_box_easy(c, m, mlen, n, pk, sk)
}

fn C.crypto_box_open_detached_afternm(m &byte, c &byte, mac &byte, clen u64, n &byte, k &byte) int

pub fn crypto_box_open_detached_afternm(m &byte, c &byte, mac &byte, clen u64, n &byte, k &byte) int {
	return C.crypto_box_open_detached_afternm(m, c, mac, clen, n, k)
}

fn C.crypto_box_open_detached(m &byte, c &byte, mac &byte, clen u64, n &byte, pk &byte, sk &byte) int

pub fn crypto_box_open_detached(m &byte, c &byte, mac &byte, clen u64, n &byte, pk &byte, sk &byte) int {
	return C.crypto_box_open_detached(m, c, mac, clen, n, pk, sk)
}

fn C.crypto_box_open_easy_afternm(m &byte, c &byte, clen u64, n &byte, k &byte) int

pub fn crypto_box_open_easy_afternm(m &byte, c &byte, clen u64, n &byte, k &byte) int {
	return C.crypto_box_open_easy_afternm(m, c, clen, n, k)
}

fn C.crypto_box_open_easy(m &byte, c &byte, clen u64, n &byte, pk &byte, sk &byte) int

pub fn crypto_box_open_easy(m &byte, c &byte, clen u64, n &byte, pk &byte, sk &byte) int {
	return C.crypto_box_open_easy(m, c, clen, n, pk, sk)
}

fn C.crypto_box_seal(c &byte, m &byte, mlen u64, pk &byte) int

pub fn crypto_box_seal(c &byte, m &byte, mlen u64, pk &byte) int {
	return C.crypto_box_seal(c, m, mlen, pk)
}

fn C.crypto_box_seal_open(m &byte, c &byte, clen u64, pk &byte, sk &byte) int

pub fn crypto_box_seal_open(m &byte, c &byte, clen u64, pk &byte, sk &byte) int {
	return C.crypto_box_seal_open(m, c, clen, pk, sk)
}

fn C.crypto_box_sealbytes() size_t

pub fn crypto_box_sealbytes() size_t {
	return C.crypto_box_sealbytes()
}

fn C.crypto_box_curve25519xsalsa20poly1305_seed_keypair(pk &byte, sk &byte, seed &byte) int

pub fn crypto_box_curve25519xsalsa20poly1305_seed_keypair(pk &byte, sk &byte, seed &byte) int {
	return C.crypto_box_curve25519xsalsa20poly1305_seed_keypair(pk, sk, seed)
}

fn C.crypto_box_curve25519xsalsa20poly1305_keypair(pk &byte, sk &byte) int

pub fn crypto_box_curve25519xsalsa20poly1305_keypair(pk &byte, sk &byte) int {
	return C.crypto_box_curve25519xsalsa20poly1305_keypair(pk, sk)
}

fn C.crypto_box_curve25519xsalsa20poly1305_beforenm(k &byte, pk &byte, sk &byte) int

pub fn crypto_box_curve25519xsalsa20poly1305_beforenm(k &byte, pk &byte, sk &byte) int {
	return C.crypto_box_curve25519xsalsa20poly1305_beforenm(k, pk, sk)
}

fn C.crypto_box_curve25519xsalsa20poly1305_afternm(c &byte, m &byte, mlen u64, n &byte, k &byte) int

pub fn crypto_box_curve25519xsalsa20poly1305_afternm(c &byte, m &byte, mlen u64, n &byte, k &byte) int {
	return C.crypto_box_curve25519xsalsa20poly1305_afternm(c, m, mlen, n, k)
}

fn C.crypto_box_curve25519xsalsa20poly1305_open_afternm(m &byte, c &byte, clen u64, n &byte, k &byte) int

pub fn crypto_box_curve25519xsalsa20poly1305_open_afternm(m &byte, c &byte, clen u64, n &byte, k &byte) int {
	return C.crypto_box_curve25519xsalsa20poly1305_open_afternm(m, c, clen, n, k)
}

fn C.crypto_box_curve25519xsalsa20poly1305(c &byte, m &byte, mlen u64, n &byte, pk &byte, sk &byte) int

pub fn crypto_box_curve25519xsalsa20poly1305(c &byte, m &byte, mlen u64, n &byte, pk &byte, sk &byte) int {
	return C.crypto_box_curve25519xsalsa20poly1305(c, m, mlen, n, pk, sk)
}

fn C.crypto_box_curve25519xsalsa20poly1305_open(m &byte, c &byte, clen u64, n &byte, pk &byte, sk &byte) int

pub fn crypto_box_curve25519xsalsa20poly1305_open(m &byte, c &byte, clen u64, n &byte, pk &byte, sk &byte) int {
	return C.crypto_box_curve25519xsalsa20poly1305_open(m, c, clen, n, pk, sk)
}

fn C.crypto_box_curve25519xsalsa20poly1305_seedbytes() size_t

pub fn crypto_box_curve25519xsalsa20poly1305_seedbytes() size_t {
	return C.crypto_box_curve25519xsalsa20poly1305_seedbytes()
}

fn C.crypto_box_curve25519xsalsa20poly1305_publickeybytes() size_t

pub fn crypto_box_curve25519xsalsa20poly1305_publickeybytes() size_t {
	return C.crypto_box_curve25519xsalsa20poly1305_publickeybytes()
}

fn C.crypto_box_curve25519xsalsa20poly1305_secretkeybytes() size_t

pub fn crypto_box_curve25519xsalsa20poly1305_secretkeybytes() size_t {
	return C.crypto_box_curve25519xsalsa20poly1305_secretkeybytes()
}

fn C.crypto_box_curve25519xsalsa20poly1305_beforenmbytes() size_t

pub fn crypto_box_curve25519xsalsa20poly1305_beforenmbytes() size_t {
	return C.crypto_box_curve25519xsalsa20poly1305_beforenmbytes()
}

fn C.crypto_box_curve25519xsalsa20poly1305_noncebytes() size_t

pub fn crypto_box_curve25519xsalsa20poly1305_noncebytes() size_t {
	return C.crypto_box_curve25519xsalsa20poly1305_noncebytes()
}

fn C.crypto_box_curve25519xsalsa20poly1305_zerobytes() size_t

pub fn crypto_box_curve25519xsalsa20poly1305_zerobytes() size_t {
	return C.crypto_box_curve25519xsalsa20poly1305_zerobytes()
}

fn C.crypto_box_curve25519xsalsa20poly1305_boxzerobytes() size_t

pub fn crypto_box_curve25519xsalsa20poly1305_boxzerobytes() size_t {
	return C.crypto_box_curve25519xsalsa20poly1305_boxzerobytes()
}

fn C.crypto_box_curve25519xsalsa20poly1305_macbytes() size_t

pub fn crypto_box_curve25519xsalsa20poly1305_macbytes() size_t {
	return C.crypto_box_curve25519xsalsa20poly1305_macbytes()
}

fn C.crypto_box_curve25519xsalsa20poly1305_messagebytes_max() size_t

pub fn crypto_box_curve25519xsalsa20poly1305_messagebytes_max() size_t {
	return C.crypto_box_curve25519xsalsa20poly1305_messagebytes_max()
}

fn C.crypto_box_curve25519xchacha20poly1305_seed_keypair(pk &byte, sk &byte, seed &byte) int

pub fn crypto_box_curve25519xchacha20poly1305_seed_keypair(pk &byte, sk &byte, seed &byte) int {
	return C.crypto_box_curve25519xchacha20poly1305_seed_keypair(pk, sk, seed)
}

fn C.crypto_box_curve25519xchacha20poly1305_keypair(pk &byte, sk &byte) int

pub fn crypto_box_curve25519xchacha20poly1305_keypair(pk &byte, sk &byte) int {
	return C.crypto_box_curve25519xchacha20poly1305_keypair(pk, sk)
}

fn C.crypto_box_curve25519xchacha20poly1305_beforenm(k &byte, pk &byte, sk &byte) int

pub fn crypto_box_curve25519xchacha20poly1305_beforenm(k &byte, pk &byte, sk &byte) int {
	return C.crypto_box_curve25519xchacha20poly1305_beforenm(k, pk, sk)
}

fn C.crypto_box_curve25519xchacha20poly1305_detached_afternm(c &byte, mac &byte, m &byte, mlen u64, n &byte, k &byte) int

pub fn crypto_box_curve25519xchacha20poly1305_detached_afternm(c &byte, mac &byte, m &byte, mlen u64, n &byte, k &byte) int {
	return C.crypto_box_curve25519xchacha20poly1305_detached_afternm(c, mac, m, mlen, n, k)
}

fn C.crypto_box_curve25519xchacha20poly1305_detached(c &byte, mac &byte, m &byte, mlen u64, n &byte, pk &byte, sk &byte) int

pub fn crypto_box_curve25519xchacha20poly1305_detached(c &byte, mac &byte, m &byte, mlen u64, n &byte, pk &byte, sk &byte) int {
	return C.crypto_box_curve25519xchacha20poly1305_detached(c, mac, m, mlen, n, pk, sk)
}

fn C.crypto_box_curve25519xchacha20poly1305_easy_afternm(c &byte, m &byte, mlen u64, n &byte, k &byte) int

pub fn crypto_box_curve25519xchacha20poly1305_easy_afternm(c &byte, m &byte, mlen u64, n &byte, k &byte) int {
	return C.crypto_box_curve25519xchacha20poly1305_easy_afternm(c, m, mlen, n, k)
}

fn C.crypto_box_curve25519xchacha20poly1305_easy(c &byte, m &byte, mlen u64, n &byte, pk &byte, sk &byte) int

pub fn crypto_box_curve25519xchacha20poly1305_easy(c &byte, m &byte, mlen u64, n &byte, pk &byte, sk &byte) int {
	return C.crypto_box_curve25519xchacha20poly1305_easy(c, m, mlen, n, pk, sk)
}

fn C.crypto_box_curve25519xchacha20poly1305_open_detached_afternm(m &byte, c &byte, mac &byte, clen u64, n &byte, k &byte) int

pub fn crypto_box_curve25519xchacha20poly1305_open_detached_afternm(m &byte, c &byte, mac &byte, clen u64, n &byte, k &byte) int {
	return C.crypto_box_curve25519xchacha20poly1305_open_detached_afternm(m, c, mac, clen, n, k)
}

fn C.crypto_box_curve25519xchacha20poly1305_open_detached(m &byte, c &byte, mac &byte, clen u64, n &byte, pk &byte, sk &byte) int

pub fn crypto_box_curve25519xchacha20poly1305_open_detached(m &byte, c &byte, mac &byte, clen u64, n &byte, pk &byte, sk &byte) int {
	return C.crypto_box_curve25519xchacha20poly1305_open_detached(m, c, mac, clen, n, pk, sk)
}

fn C.crypto_box_curve25519xchacha20poly1305_open_easy_afternm(m &byte, c &byte, clen u64, n &byte, k &byte) int

pub fn crypto_box_curve25519xchacha20poly1305_open_easy_afternm(m &byte, c &byte, clen u64, n &byte, k &byte) int {
	return C.crypto_box_curve25519xchacha20poly1305_open_easy_afternm(m, c, clen, n, k)
}

fn C.crypto_box_curve25519xchacha20poly1305_open_easy(m &byte, c &byte, clen u64, n &byte, pk &byte, sk &byte) int

pub fn crypto_box_curve25519xchacha20poly1305_open_easy(m &byte, c &byte, clen u64, n &byte, pk &byte, sk &byte) int {
	return C.crypto_box_curve25519xchacha20poly1305_open_easy(m, c, clen, n, pk, sk)
}

fn C.crypto_box_curve25519xchacha20poly1305_seedbytes() size_t

pub fn crypto_box_curve25519xchacha20poly1305_seedbytes() size_t {
	return C.crypto_box_curve25519xchacha20poly1305_seedbytes()
}

fn C.crypto_box_curve25519xchacha20poly1305_publickeybytes() size_t

pub fn crypto_box_curve25519xchacha20poly1305_publickeybytes() size_t {
	return C.crypto_box_curve25519xchacha20poly1305_publickeybytes()
}

fn C.crypto_box_curve25519xchacha20poly1305_secretkeybytes() size_t

pub fn crypto_box_curve25519xchacha20poly1305_secretkeybytes() size_t {
	return C.crypto_box_curve25519xchacha20poly1305_secretkeybytes()
}

fn C.crypto_box_curve25519xchacha20poly1305_beforenmbytes() size_t

pub fn crypto_box_curve25519xchacha20poly1305_beforenmbytes() size_t {
	return C.crypto_box_curve25519xchacha20poly1305_beforenmbytes()
}

fn C.crypto_box_curve25519xchacha20poly1305_noncebytes() size_t

pub fn crypto_box_curve25519xchacha20poly1305_noncebytes() size_t {
	return C.crypto_box_curve25519xchacha20poly1305_noncebytes()
}

fn C.crypto_box_curve25519xchacha20poly1305_macbytes() size_t

pub fn crypto_box_curve25519xchacha20poly1305_macbytes() size_t {
	return C.crypto_box_curve25519xchacha20poly1305_macbytes()
}

fn C.crypto_box_curve25519xchacha20poly1305_messagebytes_max() size_t

pub fn crypto_box_curve25519xchacha20poly1305_messagebytes_max() size_t {
	return C.crypto_box_curve25519xchacha20poly1305_messagebytes_max()
}

fn C.crypto_box_curve25519xchacha20poly1305_seal(c &byte, m &byte, mlen u64, pk &byte) int

pub fn crypto_box_curve25519xchacha20poly1305_seal(c &byte, m &byte, mlen u64, pk &byte) int {
	return C.crypto_box_curve25519xchacha20poly1305_seal(c, m, mlen, pk)
}

fn C.crypto_box_curve25519xchacha20poly1305_seal_open(m &byte, c &byte, clen u64, pk &byte, sk &byte) int

pub fn crypto_box_curve25519xchacha20poly1305_seal_open(m &byte, c &byte, clen u64, pk &byte, sk &byte) int {
	return C.crypto_box_curve25519xchacha20poly1305_seal_open(m, c, clen, pk, sk)
}

fn C.crypto_box_curve25519xchacha20poly1305_sealbytes() size_t

pub fn crypto_box_curve25519xchacha20poly1305_sealbytes() size_t {
	return C.crypto_box_curve25519xchacha20poly1305_sealbytes()
}

fn C.crypto_box_primitive() &char

pub fn crypto_box_primitive() &char {
	return C.crypto_box_primitive()
}

fn C.crypto_box_seed_keypair(pk &byte, sk &byte, seed &byte) int

pub fn crypto_box_seed_keypair(pk &byte, sk &byte, seed &byte) int {
	return C.crypto_box_seed_keypair(pk, sk, seed)
}

fn C.crypto_box_keypair(pk &byte, sk &byte) int

pub fn crypto_box_keypair(pk &byte, sk &byte) int {
	return C.crypto_box_keypair(pk, sk)
}

fn C.crypto_box_beforenm(k &byte, pk &byte, sk &byte) int

pub fn crypto_box_beforenm(k &byte, pk &byte, sk &byte) int {
	return C.crypto_box_beforenm(k, pk, sk)
}

fn C.crypto_box_afternm(c &byte, m &byte, mlen u64, n &byte, k &byte) int

pub fn crypto_box_afternm(c &byte, m &byte, mlen u64, n &byte, k &byte) int {
	return C.crypto_box_afternm(c, m, mlen, n, k)
}

fn C.crypto_box_open_afternm(m &byte, c &byte, clen u64, n &byte, k &byte) int

pub fn crypto_box_open_afternm(m &byte, c &byte, clen u64, n &byte, k &byte) int {
	return C.crypto_box_open_afternm(m, c, clen, n, k)
}

fn C.crypto_box(c &byte, m &byte, mlen u64, n &byte, pk &byte, sk &byte) int

pub fn crypto_box(c &byte, m &byte, mlen u64, n &byte, pk &byte, sk &byte) int {
	return C.crypto_box(c, m, mlen, n, pk, sk)
}

fn C.crypto_box_open(m &byte, c &byte, clen u64, n &byte, pk &byte, sk &byte) int

pub fn crypto_box_open(m &byte, c &byte, clen u64, n &byte, pk &byte, sk &byte) int {
	return C.crypto_box_open(m, c, clen, n, pk, sk)
}

fn C.sodium_bin2hex(hex &char, hex_maxlen size_t, bin &byte, bin_len size_t) &char

pub fn sodium_bin2hex(hex &char, hex_maxlen size_t, bin &byte, bin_len size_t) &char {
	return C.sodium_bin2hex(hex, hex_maxlen, bin, bin_len)
}

fn C.sodium_hex2bin(bin &byte, bin_maxlen size_t, hex &char, hex_len size_t, ignore &char, bin_len &size_t, hex_end &&char) int

pub fn sodium_hex2bin(bin &byte, bin_maxlen size_t, hex &char, hex_len size_t, ignore &char, bin_len &size_t, hex_end &&char) int {
	return C.sodium_hex2bin(bin, bin_maxlen, hex, hex_len, ignore, bin_len, hex_end)
}

fn C.b64_byte_to_char(x u32) int

pub fn b64_byte_to_char(x u32) int {
	return C.b64_byte_to_char(x)
}

fn C.b64_char_to_byte(c int) u32

pub fn b64_char_to_byte(c int) u32 {
	return C.b64_char_to_byte(c)
}

fn C.b64_byte_to_urlsafe_char(x u32) int

pub fn b64_byte_to_urlsafe_char(x u32) int {
	return C.b64_byte_to_urlsafe_char(x)
}

fn C.b64_urlsafe_char_to_byte(c int) u32

pub fn b64_urlsafe_char_to_byte(c int) u32 {
	return C.b64_urlsafe_char_to_byte(c)
}

fn C.sodium_base64_check_variant(variant int) 

pub fn sodium_base64_check_variant(variant int)  {
	C.sodium_base64_check_variant(variant)
}

fn C.sodium_base64_encoded_len(bin_len size_t, variant int) size_t

pub fn sodium_base64_encoded_len(bin_len size_t, variant int) size_t {
	return C.sodium_base64_encoded_len(bin_len, variant)
}

fn C.sodium_bin2base64(b64 &char, b64_maxlen size_t, bin &byte, bin_len size_t, variant int) &char

pub fn sodium_bin2base64(b64 &char, b64_maxlen size_t, bin &byte, bin_len size_t, variant int) &char {
	return C.sodium_bin2base64(b64, b64_maxlen, bin, bin_len, variant)
}

fn C.sodium_base642bin(bin &byte, bin_maxlen size_t, b64 &char, b64_len size_t, ignore &char, bin_len &size_t, b64_end &&char, variant int) int

pub fn sodium_base642bin(bin &byte, bin_maxlen size_t, b64 &char, b64_len size_t, ignore &char, bin_len &size_t, b64_end &&char, variant int) int {
	return C.sodium_base642bin(bin, bin_maxlen, b64, b64_len, ignore, bin_len, b64_end, variant)
}

// struct decl name="CPUFeatures_"
// typedef struct
// ['referenced', 'CPUFeatures', 'struct CPUFeatures_:struct CPUFeatures_']
struct CPUFeatures { 
	initialized int
	has_neon int
	has_armcrypto int
	has_sse2 int
	has_sse3 int
	has_ssse3 int
	has_sse41 int
	has_avx int
	has_avx2 int
	has_avx512f int
	has_pclmul int
	has_aesni int
	has_rdrand int
}
fn C.sodium_runtime_has_neon() int

pub fn sodium_runtime_has_neon() int {
	return C.sodium_runtime_has_neon()
}

fn C.sodium_runtime_has_armcrypto() int

pub fn sodium_runtime_has_armcrypto() int {
	return C.sodium_runtime_has_armcrypto()
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

fn C.sodium_crit_enter() int

pub fn sodium_crit_enter() int {
	return C.sodium_crit_enter()
}

fn C.sodium_crit_leave() int

pub fn sodium_crit_leave() int {
	return C.sodium_crit_leave()
}

fn C.sodium_misuse() 

pub fn sodium_misuse()  {
	C.sodium_misuse()
}

fn C.sodium_set_misuse_handler(handler fn ()) int

pub fn sodium_set_misuse_handler(handler fn ()) int {
	return C.sodium_set_misuse_handler(handler)
}

fn C.sodium_memzero(pnt voidptr, len size_t) 

pub fn sodium_memzero(pnt voidptr, len size_t)  {
	C.sodium_memzero(pnt, len)
}

fn C.sodium_stackzero(len size_t) 

pub fn sodium_stackzero(len size_t)  {
	C.sodium_stackzero(len)
}

fn C.sodium_memcmp(b1_ voidptr, b2_ voidptr, len size_t) int

pub fn sodium_memcmp(b1_ voidptr, b2_ voidptr, len size_t) int {
	return C.sodium_memcmp(b1_, b2_, len)
}

fn C.sodium_compare(b1_ &byte, b2_ &byte, len size_t) int

pub fn sodium_compare(b1_ &byte, b2_ &byte, len size_t) int {
	return C.sodium_compare(b1_, b2_, len)
}

fn C.sodium_is_zero(n &byte, nlen size_t) int

pub fn sodium_is_zero(n &byte, nlen size_t) int {
	return C.sodium_is_zero(n, nlen)
}

fn C.sodium_increment(n &byte, nlen size_t) 

pub fn sodium_increment(n &byte, nlen size_t)  {
	C.sodium_increment(n, nlen)
}

fn C.sodium_add(a &byte, b &byte, len size_t) 

pub fn sodium_add(a &byte, b &byte, len size_t)  {
	C.sodium_add(a, b, len)
}

fn C.sodium_sub(a &byte, b &byte, len size_t) 

pub fn sodium_sub(a &byte, b &byte, len size_t)  {
	C.sodium_sub(a, b, len)
}

fn C.sodium_mlock(addr voidptr, len size_t) int

pub fn sodium_mlock(addr voidptr, len size_t) int {
	return C.sodium_mlock(addr, len)
}

fn C.sodium_munlock(addr voidptr, len size_t) int

pub fn sodium_munlock(addr voidptr, len size_t) int {
	return C.sodium_munlock(addr, len)
}

fn C.sodium_malloc(size size_t) voidptr

pub fn sodium_malloc(size size_t) voidptr {
	return C.sodium_malloc(size)
}

fn C.sodium_allocarray(count size_t, size size_t) voidptr

pub fn sodium_allocarray(count size_t, size size_t) voidptr {
	return C.sodium_allocarray(count, size)
}

fn C.sodium_free(ptr voidptr) 

pub fn sodium_free(ptr voidptr)  {
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

fn C.sodium_pad(padded_buflen_p &size_t, buf &byte, unpadded_buflen size_t, blocksize size_t, max_buflen size_t) int

pub fn sodium_pad(padded_buflen_p &size_t, buf &byte, unpadded_buflen size_t, blocksize size_t, max_buflen size_t) int {
	return C.sodium_pad(padded_buflen_p, buf, unpadded_buflen, blocksize, max_buflen)
}

fn C.sodium_unpad(unpadded_buflen_p &size_t, buf &byte, padded_buflen size_t, blocksize size_t) int

pub fn sodium_unpad(unpadded_buflen_p &size_t, buf &byte, padded_buflen size_t, blocksize size_t) int {
	return C.sodium_unpad(unpadded_buflen_p, buf, padded_buflen, blocksize)
}

fn C.sodium_version_string() &char

pub fn sodium_version_string() &char {
	return C.sodium_version_string()
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

fn C.crypto_stream_xchacha20_keybytes() size_t

pub fn crypto_stream_xchacha20_keybytes() size_t {
	return C.crypto_stream_xchacha20_keybytes()
}

fn C.crypto_stream_xchacha20_noncebytes() size_t

pub fn crypto_stream_xchacha20_noncebytes() size_t {
	return C.crypto_stream_xchacha20_noncebytes()
}

fn C.crypto_stream_xchacha20_messagebytes_max() size_t

pub fn crypto_stream_xchacha20_messagebytes_max() size_t {
	return C.crypto_stream_xchacha20_messagebytes_max()
}

fn C.crypto_stream_xchacha20(c &byte, clen u64, n &byte, k &byte) int

pub fn crypto_stream_xchacha20(c &byte, clen u64, n &byte, k &byte) int {
	return C.crypto_stream_xchacha20(c, clen, n, k)
}

fn C.crypto_stream_xchacha20_xor_ic(c &byte, m &byte, mlen u64, n &byte, ic u64, k &byte) int

pub fn crypto_stream_xchacha20_xor_ic(c &byte, m &byte, mlen u64, n &byte, ic u64, k &byte) int {
	return C.crypto_stream_xchacha20_xor_ic(c, m, mlen, n, ic, k)
}

fn C.crypto_stream_xchacha20_xor(c &byte, m &byte, mlen u64, n &byte, k &byte) int

pub fn crypto_stream_xchacha20_xor(c &byte, m &byte, mlen u64, n &byte, k &byte) int {
	return C.crypto_stream_xchacha20_xor(c, m, mlen, n, k)
}

// struct decl name="crypto_stream_chacha20_implementation"
// typedef struct
// ['crypto_stream_chacha20_implementation', 'struct crypto_stream_chacha20_implementation:struct crypto_stream_chacha20_implementation']
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
fn C.chacha_keysetup(ctx &chacha_ctx, k &byte) 

pub fn chacha_keysetup(ctx &chacha_ctx, k &byte)  {
	C.chacha_keysetup(ctx, k)
}

fn C.chacha_ivsetup(ctx &chacha_ctx, iv &byte, counter &byte) 

pub fn chacha_ivsetup(ctx &chacha_ctx, iv &byte, counter &byte)  {
	C.chacha_ivsetup(ctx, iv, counter)
}

fn C.chacha_ietf_ivsetup(ctx &chacha_ctx, iv &byte, counter &byte) 

pub fn chacha_ietf_ivsetup(ctx &chacha_ctx, iv &byte, counter &byte)  {
	C.chacha_ietf_ivsetup(ctx, iv, counter)
}

fn C.chacha20_encrypt_bytes(ctx &chacha_ctx, m &byte, c &byte, bytes u64) 

pub fn chacha20_encrypt_bytes(ctx &chacha_ctx, m &byte, c &byte, bytes u64)  {
	C.chacha20_encrypt_bytes(ctx, m, c, bytes)
}

fn C.stream_ref(c &byte, clen u64, n &byte, k &byte) int

pub fn stream_ref(c &byte, clen u64, n &byte, k &byte) int {
	return C.stream_ref(c, clen, n, k)
}

fn C.stream_ietf_ext_ref(c &byte, clen u64, n &byte, k &byte) int

pub fn stream_ietf_ext_ref(c &byte, clen u64, n &byte, k &byte) int {
	return C.stream_ietf_ext_ref(c, clen, n, k)
}

fn C.stream_ref_xor_ic(c &byte, m &byte, mlen u64, n &byte, ic u64, k &byte) int

pub fn stream_ref_xor_ic(c &byte, m &byte, mlen u64, n &byte, ic u64, k &byte) int {
	return C.stream_ref_xor_ic(c, m, mlen, n, ic, k)
}

fn C.stream_ietf_ext_ref_xor_ic(c &byte, m &byte, mlen u64, n &byte, ic u32, k &byte) int

pub fn stream_ietf_ext_ref_xor_ic(c &byte, m &byte, mlen u64, n &byte, ic u32, k &byte) int {
	return C.stream_ietf_ext_ref_xor_ic(c, m, mlen, n, ic, k)
}

// struct decl name="crypto_stream_chacha20_implementation"
// typedef struct
// ['referenced', 'crypto_stream_chacha20_implementation', 'struct crypto_stream_chacha20_implementation:struct crypto_stream_chacha20_implementation']
fn C.crypto_stream_chacha20(c &byte, clen u64, n &byte, k &byte) int

pub fn crypto_stream_chacha20(c &byte, clen u64, n &byte, k &byte) int {
	return C.crypto_stream_chacha20(c, clen, n, k)
}

fn C.crypto_stream_chacha20_xor_ic(c &byte, m &byte, mlen u64, n &byte, ic u64, k &byte) int

pub fn crypto_stream_chacha20_xor_ic(c &byte, m &byte, mlen u64, n &byte, ic u64, k &byte) int {
	return C.crypto_stream_chacha20_xor_ic(c, m, mlen, n, ic, k)
}

fn C.crypto_stream_chacha20_xor(c &byte, m &byte, mlen u64, n &byte, k &byte) int

pub fn crypto_stream_chacha20_xor(c &byte, m &byte, mlen u64, n &byte, k &byte) int {
	return C.crypto_stream_chacha20_xor(c, m, mlen, n, k)
}

fn C.crypto_stream_chacha20_ietf_ext(c &byte, clen u64, n &byte, k &byte) int

pub fn crypto_stream_chacha20_ietf_ext(c &byte, clen u64, n &byte, k &byte) int {
	return C.crypto_stream_chacha20_ietf_ext(c, clen, n, k)
}

fn C.crypto_stream_chacha20_ietf_ext_xor_ic(c &byte, m &byte, mlen u64, n &byte, ic u32, k &byte) int

pub fn crypto_stream_chacha20_ietf_ext_xor_ic(c &byte, m &byte, mlen u64, n &byte, ic u32, k &byte) int {
	return C.crypto_stream_chacha20_ietf_ext_xor_ic(c, m, mlen, n, ic, k)
}

fn C.crypto_stream_chacha20_ietf_ext_xor(c &byte, m &byte, mlen u64, n &byte, k &byte) int

pub fn crypto_stream_chacha20_ietf_ext_xor(c &byte, m &byte, mlen u64, n &byte, k &byte) int {
	return C.crypto_stream_chacha20_ietf_ext_xor(c, m, mlen, n, k)
}

fn C.crypto_stream_chacha20_ietf(c &byte, clen u64, n &byte, k &byte) int

pub fn crypto_stream_chacha20_ietf(c &byte, clen u64, n &byte, k &byte) int {
	return C.crypto_stream_chacha20_ietf(c, clen, n, k)
}

fn C.crypto_stream_chacha20_ietf_xor_ic(c &byte, m &byte, mlen u64, n &byte, ic u32, k &byte) int

pub fn crypto_stream_chacha20_ietf_xor_ic(c &byte, m &byte, mlen u64, n &byte, ic u32, k &byte) int {
	return C.crypto_stream_chacha20_ietf_xor_ic(c, m, mlen, n, ic, k)
}

fn C.crypto_stream_chacha20_ietf_xor(c &byte, m &byte, mlen u64, n &byte, k &byte) int

pub fn crypto_stream_chacha20_ietf_xor(c &byte, m &byte, mlen u64, n &byte, k &byte) int {
	return C.crypto_stream_chacha20_ietf_xor(c, m, mlen, n, k)
}

// struct decl name="crypto_stream_salsa20_implementation"
// typedef struct
// ['crypto_stream_salsa20_implementation', 'struct crypto_stream_salsa20_implementation:struct crypto_stream_salsa20_implementation']
struct crypto_stream_salsa20_implementation { 
	stream fn (byteptr, u64, byteptr, byteptr) int
	stream_xor_ic fn (byteptr, byteptr, u64, byteptr, u64, byteptr) int
}
// struct decl name="crypto_stream_salsa20_implementation"
// typedef struct
// ['referenced', 'crypto_stream_salsa20_implementation', 'struct crypto_stream_salsa20_implementation:struct crypto_stream_salsa20_implementation']
fn C.crypto_stream_salsa20(c &byte, clen u64, n &byte, k &byte) int

pub fn crypto_stream_salsa20(c &byte, clen u64, n &byte, k &byte) int {
	return C.crypto_stream_salsa20(c, clen, n, k)
}

fn C.crypto_stream_salsa20_xor_ic(c &byte, m &byte, mlen u64, n &byte, ic u64, k &byte) int

pub fn crypto_stream_salsa20_xor_ic(c &byte, m &byte, mlen u64, n &byte, ic u64, k &byte) int {
	return C.crypto_stream_salsa20_xor_ic(c, m, mlen, n, ic, k)
}

fn C.crypto_stream_salsa20_xor(c &byte, m &byte, mlen u64, n &byte, k &byte) int

pub fn crypto_stream_salsa20_xor(c &byte, m &byte, mlen u64, n &byte, k &byte) int {
	return C.crypto_stream_salsa20_xor(c, m, mlen, n, k)
}

// struct decl name="crypto_stream_salsa20_implementation"
// typedef struct
// ['crypto_stream_salsa20_implementation', 'struct crypto_stream_salsa20_implementation:struct crypto_stream_salsa20_implementation']
fn C.crypto_stream_primitive() &char

pub fn crypto_stream_primitive() &char {
	return C.crypto_stream_primitive()
}

fn C.crypto_stream(c &byte, clen u64, n &byte, k &byte) int

pub fn crypto_stream(c &byte, clen u64, n &byte, k &byte) int {
	return C.crypto_stream(c, clen, n, k)
}

fn C.crypto_stream_xor(c &byte, m &byte, mlen u64, n &byte, k &byte) int

pub fn crypto_stream_xor(c &byte, m &byte, mlen u64, n &byte, k &byte) int {
	return C.crypto_stream_xor(c, m, mlen, n, k)
}

fn C.crypto_stream_salsa2012(c &byte, clen u64, n &byte, k &byte) int

pub fn crypto_stream_salsa2012(c &byte, clen u64, n &byte, k &byte) int {
	return C.crypto_stream_salsa2012(c, clen, n, k)
}

fn C.crypto_stream_salsa2012_xor(c &byte, m &byte, mlen u64, n &byte, k &byte) int

pub fn crypto_stream_salsa2012_xor(c &byte, m &byte, mlen u64, n &byte, k &byte) int {
	return C.crypto_stream_salsa2012_xor(c, m, mlen, n, k)
}

fn C.crypto_stream_salsa208(c &byte, clen u64, n &byte, k &byte) int

pub fn crypto_stream_salsa208(c &byte, clen u64, n &byte, k &byte) int {
	return C.crypto_stream_salsa208(c, clen, n, k)
}

fn C.crypto_stream_salsa208_xor(c &byte, m &byte, mlen u64, n &byte, k &byte) int

pub fn crypto_stream_salsa208_xor(c &byte, m &byte, mlen u64, n &byte, k &byte) int {
	return C.crypto_stream_salsa208_xor(c, m, mlen, n, k)
}

fn C.crypto_stream_xsalsa20(c &byte, clen u64, n &byte, k &byte) int

pub fn crypto_stream_xsalsa20(c &byte, clen u64, n &byte, k &byte) int {
	return C.crypto_stream_xsalsa20(c, clen, n, k)
}

fn C.crypto_stream_xsalsa20_xor(c &byte, m &byte, mlen u64, n &byte, k &byte) int

pub fn crypto_stream_xsalsa20_xor(c &byte, m &byte, mlen u64, n &byte, k &byte) int {
	return C.crypto_stream_xsalsa20_xor(c, m, mlen, n, k)
}

fn C.be64enc_vect(dst &byte, src &u64, len size_t) 

pub fn be64enc_vect(dst &byte, src &u64, len size_t)  {
	C.be64enc_vect(dst, src, len)
}

fn C.be64dec_vect(dst &u64, src &byte, len size_t) 

pub fn be64dec_vect(dst &u64, src &byte, len size_t)  {
	C.be64dec_vect(dst, src, len)
}

fn C.SHA512_Transform(state &u64, block &byte, W &u64, S &u64) 

pub fn SHA512_Transform(state &u64, block &byte, W &u64, S &u64)  {
	C.SHA512_Transform(state, block, W, S)
}

fn C.crypto_hash_sha512(out &byte, in_ &byte, inlen u64) int

pub fn crypto_hash_sha512(out &byte, in_ &byte, inlen u64) int {
	return C.crypto_hash_sha512(out, in_, inlen)
}

fn C.be32enc_vect(dst &byte, src &u32, len size_t) 

pub fn be32enc_vect(dst &byte, src &u32, len size_t)  {
	C.be32enc_vect(dst, src, len)
}

fn C.be32dec_vect(dst &u32, src &byte, len size_t) 

pub fn be32dec_vect(dst &u32, src &byte, len size_t)  {
	C.be32dec_vect(dst, src, len)
}

fn C.SHA256_Transform(state &u32, block &byte, W &u32, S &u32) 

pub fn SHA256_Transform(state &u32, block &byte, W &u32, S &u32)  {
	C.SHA256_Transform(state, block, W, S)
}

fn C.crypto_hash_sha256(out &byte, in_ &byte, inlen u64) int

pub fn crypto_hash_sha256(out &byte, in_ &byte, inlen u64) int {
	return C.crypto_hash_sha256(out, in_, inlen)
}

fn C.crypto_hash(out &byte, in_ &byte, inlen u64) int

pub fn crypto_hash(out &byte, in_ &byte, inlen u64) int {
	return C.crypto_hash(out, in_, inlen)
}

fn C.crypto_hash_primitive() &char

pub fn crypto_hash_primitive() &char {
	return C.crypto_hash_primitive()
}

fn C.crypto_aead_xchacha20poly1305_ietf_encrypt_detached(c &byte, mac &byte, maclen_p &u64, m &byte, mlen u64, ad &byte, adlen u64, nsec &byte, npub &byte, k &byte) int

pub fn crypto_aead_xchacha20poly1305_ietf_encrypt_detached(c &byte, mac &byte, maclen_p &u64, m &byte, mlen u64, ad &byte, adlen u64, nsec &byte, npub &byte, k &byte) int {
	return C.crypto_aead_xchacha20poly1305_ietf_encrypt_detached(c, mac, maclen_p, m, mlen, ad, adlen, nsec, npub, k)
}

fn C.crypto_aead_xchacha20poly1305_ietf_encrypt(c &byte, clen_p &u64, m &byte, mlen u64, ad &byte, adlen u64, nsec &byte, npub &byte, k &byte) int

pub fn crypto_aead_xchacha20poly1305_ietf_encrypt(c &byte, clen_p &u64, m &byte, mlen u64, ad &byte, adlen u64, nsec &byte, npub &byte, k &byte) int {
	return C.crypto_aead_xchacha20poly1305_ietf_encrypt(c, clen_p, m, mlen, ad, adlen, nsec, npub, k)
}

fn C.crypto_aead_xchacha20poly1305_ietf_decrypt_detached(m &byte, nsec &byte, c &byte, clen u64, mac &byte, ad &byte, adlen u64, npub &byte, k &byte) int

pub fn crypto_aead_xchacha20poly1305_ietf_decrypt_detached(m &byte, nsec &byte, c &byte, clen u64, mac &byte, ad &byte, adlen u64, npub &byte, k &byte) int {
	return C.crypto_aead_xchacha20poly1305_ietf_decrypt_detached(m, nsec, c, clen, mac, ad, adlen, npub, k)
}

fn C.crypto_aead_xchacha20poly1305_ietf_decrypt(m &byte, mlen_p &u64, nsec &byte, c &byte, clen u64, ad &byte, adlen u64, npub &byte, k &byte) int

pub fn crypto_aead_xchacha20poly1305_ietf_decrypt(m &byte, mlen_p &u64, nsec &byte, c &byte, clen u64, ad &byte, adlen u64, npub &byte, k &byte) int {
	return C.crypto_aead_xchacha20poly1305_ietf_decrypt(m, mlen_p, nsec, c, clen, ad, adlen, npub, k)
}

fn C.crypto_aead_xchacha20poly1305_ietf_keybytes() size_t

pub fn crypto_aead_xchacha20poly1305_ietf_keybytes() size_t {
	return C.crypto_aead_xchacha20poly1305_ietf_keybytes()
}

fn C.crypto_aead_xchacha20poly1305_ietf_npubbytes() size_t

pub fn crypto_aead_xchacha20poly1305_ietf_npubbytes() size_t {
	return C.crypto_aead_xchacha20poly1305_ietf_npubbytes()
}

fn C.crypto_aead_xchacha20poly1305_ietf_nsecbytes() size_t

pub fn crypto_aead_xchacha20poly1305_ietf_nsecbytes() size_t {
	return C.crypto_aead_xchacha20poly1305_ietf_nsecbytes()
}

fn C.crypto_aead_xchacha20poly1305_ietf_abytes() size_t

pub fn crypto_aead_xchacha20poly1305_ietf_abytes() size_t {
	return C.crypto_aead_xchacha20poly1305_ietf_abytes()
}

fn C.crypto_aead_xchacha20poly1305_ietf_messagebytes_max() size_t

pub fn crypto_aead_xchacha20poly1305_ietf_messagebytes_max() size_t {
	return C.crypto_aead_xchacha20poly1305_ietf_messagebytes_max()
}

fn C.crypto_aead_aegis128l_keybytes() size_t

pub fn crypto_aead_aegis128l_keybytes() size_t {
	return C.crypto_aead_aegis128l_keybytes()
}

fn C.crypto_aead_aegis128l_nsecbytes() size_t

pub fn crypto_aead_aegis128l_nsecbytes() size_t {
	return C.crypto_aead_aegis128l_nsecbytes()
}

fn C.crypto_aead_aegis128l_npubbytes() size_t

pub fn crypto_aead_aegis128l_npubbytes() size_t {
	return C.crypto_aead_aegis128l_npubbytes()
}

fn C.crypto_aead_aegis128l_abytes() size_t

pub fn crypto_aead_aegis128l_abytes() size_t {
	return C.crypto_aead_aegis128l_abytes()
}

fn C.crypto_aead_aegis128l_messagebytes_max() size_t

pub fn crypto_aead_aegis128l_messagebytes_max() size_t {
	return C.crypto_aead_aegis128l_messagebytes_max()
}

fn C.crypto_aead_aegis128l_encrypt_detached(c &byte, mac &byte, maclen_p &u64, m &byte, mlen u64, ad &byte, adlen u64, nsec &byte, npub &byte, k &byte) int

pub fn crypto_aead_aegis128l_encrypt_detached(c &byte, mac &byte, maclen_p &u64, m &byte, mlen u64, ad &byte, adlen u64, nsec &byte, npub &byte, k &byte) int {
	return C.crypto_aead_aegis128l_encrypt_detached(c, mac, maclen_p, m, mlen, ad, adlen, nsec, npub, k)
}

fn C.crypto_aead_aegis128l_encrypt(c &byte, clen_p &u64, m &byte, mlen u64, ad &byte, adlen u64, nsec &byte, npub &byte, k &byte) int

pub fn crypto_aead_aegis128l_encrypt(c &byte, clen_p &u64, m &byte, mlen u64, ad &byte, adlen u64, nsec &byte, npub &byte, k &byte) int {
	return C.crypto_aead_aegis128l_encrypt(c, clen_p, m, mlen, ad, adlen, nsec, npub, k)
}

fn C.crypto_aead_aegis128l_decrypt_detached(m &byte, nsec &byte, c &byte, clen u64, mac &byte, ad &byte, adlen u64, npub &byte, k &byte) int

pub fn crypto_aead_aegis128l_decrypt_detached(m &byte, nsec &byte, c &byte, clen u64, mac &byte, ad &byte, adlen u64, npub &byte, k &byte) int {
	return C.crypto_aead_aegis128l_decrypt_detached(m, nsec, c, clen, mac, ad, adlen, npub, k)
}

fn C.crypto_aead_aegis128l_decrypt(m &byte, mlen_p &u64, nsec &byte, c &byte, clen u64, ad &byte, adlen u64, npub &byte, k &byte) int

pub fn crypto_aead_aegis128l_decrypt(m &byte, mlen_p &u64, nsec &byte, c &byte, clen u64, ad &byte, adlen u64, npub &byte, k &byte) int {
	return C.crypto_aead_aegis128l_decrypt(m, mlen_p, nsec, c, clen, ad, adlen, npub, k)
}

fn C.crypto_aead_aegis128l_is_available() int

pub fn crypto_aead_aegis128l_is_available() int {
	return C.crypto_aead_aegis128l_is_available()
}

fn C.crypto_aead_aegis256_keybytes() size_t

pub fn crypto_aead_aegis256_keybytes() size_t {
	return C.crypto_aead_aegis256_keybytes()
}

fn C.crypto_aead_aegis256_nsecbytes() size_t

pub fn crypto_aead_aegis256_nsecbytes() size_t {
	return C.crypto_aead_aegis256_nsecbytes()
}

fn C.crypto_aead_aegis256_npubbytes() size_t

pub fn crypto_aead_aegis256_npubbytes() size_t {
	return C.crypto_aead_aegis256_npubbytes()
}

fn C.crypto_aead_aegis256_abytes() size_t

pub fn crypto_aead_aegis256_abytes() size_t {
	return C.crypto_aead_aegis256_abytes()
}

fn C.crypto_aead_aegis256_messagebytes_max() size_t

pub fn crypto_aead_aegis256_messagebytes_max() size_t {
	return C.crypto_aead_aegis256_messagebytes_max()
}

fn C.crypto_aead_aegis256_encrypt_detached(c &byte, mac &byte, maclen_p &u64, m &byte, mlen u64, ad &byte, adlen u64, nsec &byte, npub &byte, k &byte) int

pub fn crypto_aead_aegis256_encrypt_detached(c &byte, mac &byte, maclen_p &u64, m &byte, mlen u64, ad &byte, adlen u64, nsec &byte, npub &byte, k &byte) int {
	return C.crypto_aead_aegis256_encrypt_detached(c, mac, maclen_p, m, mlen, ad, adlen, nsec, npub, k)
}

fn C.crypto_aead_aegis256_encrypt(c &byte, clen_p &u64, m &byte, mlen u64, ad &byte, adlen u64, nsec &byte, npub &byte, k &byte) int

pub fn crypto_aead_aegis256_encrypt(c &byte, clen_p &u64, m &byte, mlen u64, ad &byte, adlen u64, nsec &byte, npub &byte, k &byte) int {
	return C.crypto_aead_aegis256_encrypt(c, clen_p, m, mlen, ad, adlen, nsec, npub, k)
}

fn C.crypto_aead_aegis256_decrypt_detached(m &byte, nsec &byte, c &byte, clen u64, mac &byte, ad &byte, adlen u64, npub &byte, k &byte) int

pub fn crypto_aead_aegis256_decrypt_detached(m &byte, nsec &byte, c &byte, clen u64, mac &byte, ad &byte, adlen u64, npub &byte, k &byte) int {
	return C.crypto_aead_aegis256_decrypt_detached(m, nsec, c, clen, mac, ad, adlen, npub, k)
}

fn C.crypto_aead_aegis256_decrypt(m &byte, mlen_p &u64, nsec &byte, c &byte, clen u64, ad &byte, adlen u64, npub &byte, k &byte) int

pub fn crypto_aead_aegis256_decrypt(m &byte, mlen_p &u64, nsec &byte, c &byte, clen u64, ad &byte, adlen u64, npub &byte, k &byte) int {
	return C.crypto_aead_aegis256_decrypt(m, mlen_p, nsec, c, clen, ad, adlen, npub, k)
}

fn C.crypto_aead_aegis256_is_available() int

pub fn crypto_aead_aegis256_is_available() int {
	return C.crypto_aead_aegis256_is_available()
}

fn C.crypto_aead_aes256gcm_encrypt_detached(c &byte, mac &byte, maclen_p &u64, m &byte, mlen u64, ad &byte, adlen u64, nsec &byte, npub &byte, k &byte) int

pub fn crypto_aead_aes256gcm_encrypt_detached(c &byte, mac &byte, maclen_p &u64, m &byte, mlen u64, ad &byte, adlen u64, nsec &byte, npub &byte, k &byte) int {
	return C.crypto_aead_aes256gcm_encrypt_detached(c, mac, maclen_p, m, mlen, ad, adlen, nsec, npub, k)
}

fn C.crypto_aead_aes256gcm_encrypt(c &byte, clen_p &u64, m &byte, mlen u64, ad &byte, adlen u64, nsec &byte, npub &byte, k &byte) int

pub fn crypto_aead_aes256gcm_encrypt(c &byte, clen_p &u64, m &byte, mlen u64, ad &byte, adlen u64, nsec &byte, npub &byte, k &byte) int {
	return C.crypto_aead_aes256gcm_encrypt(c, clen_p, m, mlen, ad, adlen, nsec, npub, k)
}

fn C.crypto_aead_aes256gcm_decrypt_detached(m &byte, nsec &byte, c &byte, clen u64, mac &byte, ad &byte, adlen u64, npub &byte, k &byte) int

pub fn crypto_aead_aes256gcm_decrypt_detached(m &byte, nsec &byte, c &byte, clen u64, mac &byte, ad &byte, adlen u64, npub &byte, k &byte) int {
	return C.crypto_aead_aes256gcm_decrypt_detached(m, nsec, c, clen, mac, ad, adlen, npub, k)
}

fn C.crypto_aead_aes256gcm_decrypt(m &byte, mlen_p &u64, nsec &byte, c &byte, clen u64, ad &byte, adlen u64, npub &byte, k &byte) int

pub fn crypto_aead_aes256gcm_decrypt(m &byte, mlen_p &u64, nsec &byte, c &byte, clen u64, ad &byte, adlen u64, npub &byte, k &byte) int {
	return C.crypto_aead_aes256gcm_decrypt(m, mlen_p, nsec, c, clen, ad, adlen, npub, k)
}

fn C.crypto_aead_aes256gcm_is_available() int

pub fn crypto_aead_aes256gcm_is_available() int {
	return C.crypto_aead_aes256gcm_is_available()
}

fn C.crypto_aead_aes256gcm_keybytes() size_t

pub fn crypto_aead_aes256gcm_keybytes() size_t {
	return C.crypto_aead_aes256gcm_keybytes()
}

fn C.crypto_aead_aes256gcm_nsecbytes() size_t

pub fn crypto_aead_aes256gcm_nsecbytes() size_t {
	return C.crypto_aead_aes256gcm_nsecbytes()
}

fn C.crypto_aead_aes256gcm_npubbytes() size_t

pub fn crypto_aead_aes256gcm_npubbytes() size_t {
	return C.crypto_aead_aes256gcm_npubbytes()
}

fn C.crypto_aead_aes256gcm_abytes() size_t

pub fn crypto_aead_aes256gcm_abytes() size_t {
	return C.crypto_aead_aes256gcm_abytes()
}

fn C.crypto_aead_aes256gcm_statebytes() size_t

pub fn crypto_aead_aes256gcm_statebytes() size_t {
	return C.crypto_aead_aes256gcm_statebytes()
}

fn C.crypto_aead_aes256gcm_messagebytes_max() size_t

pub fn crypto_aead_aes256gcm_messagebytes_max() size_t {
	return C.crypto_aead_aes256gcm_messagebytes_max()
}

fn C.crypto_aead_chacha20poly1305_encrypt_detached(c &byte, mac &byte, maclen_p &u64, m &byte, mlen u64, ad &byte, adlen u64, nsec &byte, npub &byte, k &byte) int

pub fn crypto_aead_chacha20poly1305_encrypt_detached(c &byte, mac &byte, maclen_p &u64, m &byte, mlen u64, ad &byte, adlen u64, nsec &byte, npub &byte, k &byte) int {
	return C.crypto_aead_chacha20poly1305_encrypt_detached(c, mac, maclen_p, m, mlen, ad, adlen, nsec, npub, k)
}

fn C.crypto_aead_chacha20poly1305_encrypt(c &byte, clen_p &u64, m &byte, mlen u64, ad &byte, adlen u64, nsec &byte, npub &byte, k &byte) int

pub fn crypto_aead_chacha20poly1305_encrypt(c &byte, clen_p &u64, m &byte, mlen u64, ad &byte, adlen u64, nsec &byte, npub &byte, k &byte) int {
	return C.crypto_aead_chacha20poly1305_encrypt(c, clen_p, m, mlen, ad, adlen, nsec, npub, k)
}

fn C.crypto_aead_chacha20poly1305_ietf_encrypt_detached(c &byte, mac &byte, maclen_p &u64, m &byte, mlen u64, ad &byte, adlen u64, nsec &byte, npub &byte, k &byte) int

pub fn crypto_aead_chacha20poly1305_ietf_encrypt_detached(c &byte, mac &byte, maclen_p &u64, m &byte, mlen u64, ad &byte, adlen u64, nsec &byte, npub &byte, k &byte) int {
	return C.crypto_aead_chacha20poly1305_ietf_encrypt_detached(c, mac, maclen_p, m, mlen, ad, adlen, nsec, npub, k)
}

fn C.crypto_aead_chacha20poly1305_ietf_encrypt(c &byte, clen_p &u64, m &byte, mlen u64, ad &byte, adlen u64, nsec &byte, npub &byte, k &byte) int

pub fn crypto_aead_chacha20poly1305_ietf_encrypt(c &byte, clen_p &u64, m &byte, mlen u64, ad &byte, adlen u64, nsec &byte, npub &byte, k &byte) int {
	return C.crypto_aead_chacha20poly1305_ietf_encrypt(c, clen_p, m, mlen, ad, adlen, nsec, npub, k)
}

fn C.crypto_aead_chacha20poly1305_decrypt_detached(m &byte, nsec &byte, c &byte, clen u64, mac &byte, ad &byte, adlen u64, npub &byte, k &byte) int

pub fn crypto_aead_chacha20poly1305_decrypt_detached(m &byte, nsec &byte, c &byte, clen u64, mac &byte, ad &byte, adlen u64, npub &byte, k &byte) int {
	return C.crypto_aead_chacha20poly1305_decrypt_detached(m, nsec, c, clen, mac, ad, adlen, npub, k)
}

fn C.crypto_aead_chacha20poly1305_decrypt(m &byte, mlen_p &u64, nsec &byte, c &byte, clen u64, ad &byte, adlen u64, npub &byte, k &byte) int

pub fn crypto_aead_chacha20poly1305_decrypt(m &byte, mlen_p &u64, nsec &byte, c &byte, clen u64, ad &byte, adlen u64, npub &byte, k &byte) int {
	return C.crypto_aead_chacha20poly1305_decrypt(m, mlen_p, nsec, c, clen, ad, adlen, npub, k)
}

fn C.crypto_aead_chacha20poly1305_ietf_decrypt_detached(m &byte, nsec &byte, c &byte, clen u64, mac &byte, ad &byte, adlen u64, npub &byte, k &byte) int

pub fn crypto_aead_chacha20poly1305_ietf_decrypt_detached(m &byte, nsec &byte, c &byte, clen u64, mac &byte, ad &byte, adlen u64, npub &byte, k &byte) int {
	return C.crypto_aead_chacha20poly1305_ietf_decrypt_detached(m, nsec, c, clen, mac, ad, adlen, npub, k)
}

fn C.crypto_aead_chacha20poly1305_ietf_decrypt(m &byte, mlen_p &u64, nsec &byte, c &byte, clen u64, ad &byte, adlen u64, npub &byte, k &byte) int

pub fn crypto_aead_chacha20poly1305_ietf_decrypt(m &byte, mlen_p &u64, nsec &byte, c &byte, clen u64, ad &byte, adlen u64, npub &byte, k &byte) int {
	return C.crypto_aead_chacha20poly1305_ietf_decrypt(m, mlen_p, nsec, c, clen, ad, adlen, npub, k)
}

fn C.crypto_aead_chacha20poly1305_ietf_keybytes() size_t

pub fn crypto_aead_chacha20poly1305_ietf_keybytes() size_t {
	return C.crypto_aead_chacha20poly1305_ietf_keybytes()
}

fn C.crypto_aead_chacha20poly1305_ietf_npubbytes() size_t

pub fn crypto_aead_chacha20poly1305_ietf_npubbytes() size_t {
	return C.crypto_aead_chacha20poly1305_ietf_npubbytes()
}

fn C.crypto_aead_chacha20poly1305_ietf_nsecbytes() size_t

pub fn crypto_aead_chacha20poly1305_ietf_nsecbytes() size_t {
	return C.crypto_aead_chacha20poly1305_ietf_nsecbytes()
}

fn C.crypto_aead_chacha20poly1305_ietf_abytes() size_t

pub fn crypto_aead_chacha20poly1305_ietf_abytes() size_t {
	return C.crypto_aead_chacha20poly1305_ietf_abytes()
}

fn C.crypto_aead_chacha20poly1305_ietf_messagebytes_max() size_t

pub fn crypto_aead_chacha20poly1305_ietf_messagebytes_max() size_t {
	return C.crypto_aead_chacha20poly1305_ietf_messagebytes_max()
}

fn C.crypto_aead_chacha20poly1305_keybytes() size_t

pub fn crypto_aead_chacha20poly1305_keybytes() size_t {
	return C.crypto_aead_chacha20poly1305_keybytes()
}

fn C.crypto_aead_chacha20poly1305_npubbytes() size_t

pub fn crypto_aead_chacha20poly1305_npubbytes() size_t {
	return C.crypto_aead_chacha20poly1305_npubbytes()
}

fn C.crypto_aead_chacha20poly1305_nsecbytes() size_t

pub fn crypto_aead_chacha20poly1305_nsecbytes() size_t {
	return C.crypto_aead_chacha20poly1305_nsecbytes()
}

fn C.crypto_aead_chacha20poly1305_abytes() size_t

pub fn crypto_aead_chacha20poly1305_abytes() size_t {
	return C.crypto_aead_chacha20poly1305_abytes()
}

fn C.crypto_aead_chacha20poly1305_messagebytes_max() size_t

pub fn crypto_aead_chacha20poly1305_messagebytes_max() size_t {
	return C.crypto_aead_chacha20poly1305_messagebytes_max()
}

fn C.crypto_secretstream_xchacha20poly1305_statebytes() size_t

pub fn crypto_secretstream_xchacha20poly1305_statebytes() size_t {
	return C.crypto_secretstream_xchacha20poly1305_statebytes()
}

fn C.crypto_secretstream_xchacha20poly1305_abytes() size_t

pub fn crypto_secretstream_xchacha20poly1305_abytes() size_t {
	return C.crypto_secretstream_xchacha20poly1305_abytes()
}

fn C.crypto_secretstream_xchacha20poly1305_headerbytes() size_t

pub fn crypto_secretstream_xchacha20poly1305_headerbytes() size_t {
	return C.crypto_secretstream_xchacha20poly1305_headerbytes()
}

fn C.crypto_secretstream_xchacha20poly1305_keybytes() size_t

pub fn crypto_secretstream_xchacha20poly1305_keybytes() size_t {
	return C.crypto_secretstream_xchacha20poly1305_keybytes()
}

fn C.crypto_secretstream_xchacha20poly1305_messagebytes_max() size_t

pub fn crypto_secretstream_xchacha20poly1305_messagebytes_max() size_t {
	return C.crypto_secretstream_xchacha20poly1305_messagebytes_max()
}

fn C.crypto_secretstream_xchacha20poly1305_tag_message() byte

pub fn crypto_secretstream_xchacha20poly1305_tag_message() byte {
	return C.crypto_secretstream_xchacha20poly1305_tag_message()
}

fn C.crypto_secretstream_xchacha20poly1305_tag_push() byte

pub fn crypto_secretstream_xchacha20poly1305_tag_push() byte {
	return C.crypto_secretstream_xchacha20poly1305_tag_push()
}

fn C.crypto_secretstream_xchacha20poly1305_tag_rekey() byte

pub fn crypto_secretstream_xchacha20poly1305_tag_rekey() byte {
	return C.crypto_secretstream_xchacha20poly1305_tag_rekey()
}

fn C.crypto_secretstream_xchacha20poly1305_tag_final() byte

pub fn crypto_secretstream_xchacha20poly1305_tag_final() byte {
	return C.crypto_secretstream_xchacha20poly1305_tag_final()
}

fn C.crypto_core_salsa(out &byte, in_ &byte, k &byte, c &byte, rounds int) 

pub fn crypto_core_salsa(out &byte, in_ &byte, k &byte, c &byte, rounds int)  {
	C.crypto_core_salsa(out, in_, k, c, rounds)
}

fn C.crypto_core_salsa20(out &byte, in_ &byte, k &byte, c &byte) int

pub fn crypto_core_salsa20(out &byte, in_ &byte, k &byte, c &byte) int {
	return C.crypto_core_salsa20(out, in_, k, c)
}

fn C.crypto_core_salsa20_outputbytes() size_t

pub fn crypto_core_salsa20_outputbytes() size_t {
	return C.crypto_core_salsa20_outputbytes()
}

fn C.crypto_core_salsa20_inputbytes() size_t

pub fn crypto_core_salsa20_inputbytes() size_t {
	return C.crypto_core_salsa20_inputbytes()
}

fn C.crypto_core_salsa20_keybytes() size_t

pub fn crypto_core_salsa20_keybytes() size_t {
	return C.crypto_core_salsa20_keybytes()
}

fn C.crypto_core_salsa20_constbytes() size_t

pub fn crypto_core_salsa20_constbytes() size_t {
	return C.crypto_core_salsa20_constbytes()
}

fn C.crypto_core_salsa2012(out &byte, in_ &byte, k &byte, c &byte) int

pub fn crypto_core_salsa2012(out &byte, in_ &byte, k &byte, c &byte) int {
	return C.crypto_core_salsa2012(out, in_, k, c)
}

fn C.crypto_core_salsa2012_outputbytes() size_t

pub fn crypto_core_salsa2012_outputbytes() size_t {
	return C.crypto_core_salsa2012_outputbytes()
}

fn C.crypto_core_salsa2012_inputbytes() size_t

pub fn crypto_core_salsa2012_inputbytes() size_t {
	return C.crypto_core_salsa2012_inputbytes()
}

fn C.crypto_core_salsa2012_keybytes() size_t

pub fn crypto_core_salsa2012_keybytes() size_t {
	return C.crypto_core_salsa2012_keybytes()
}

fn C.crypto_core_salsa2012_constbytes() size_t

pub fn crypto_core_salsa2012_constbytes() size_t {
	return C.crypto_core_salsa2012_constbytes()
}

fn C.crypto_core_salsa208(out &byte, in_ &byte, k &byte, c &byte) int

pub fn crypto_core_salsa208(out &byte, in_ &byte, k &byte, c &byte) int {
	return C.crypto_core_salsa208(out, in_, k, c)
}

fn C.crypto_core_salsa208_outputbytes() size_t

pub fn crypto_core_salsa208_outputbytes() size_t {
	return C.crypto_core_salsa208_outputbytes()
}

fn C.crypto_core_salsa208_inputbytes() size_t

pub fn crypto_core_salsa208_inputbytes() size_t {
	return C.crypto_core_salsa208_inputbytes()
}

fn C.crypto_core_salsa208_keybytes() size_t

pub fn crypto_core_salsa208_keybytes() size_t {
	return C.crypto_core_salsa208_keybytes()
}

fn C.crypto_core_salsa208_constbytes() size_t

pub fn crypto_core_salsa208_constbytes() size_t {
	return C.crypto_core_salsa208_constbytes()
}

fn C.crypto_core_hchacha20(out &byte, in_ &byte, k &byte, c &byte) int

pub fn crypto_core_hchacha20(out &byte, in_ &byte, k &byte, c &byte) int {
	return C.crypto_core_hchacha20(out, in_, k, c)
}

fn C.crypto_core_hchacha20_outputbytes() size_t

pub fn crypto_core_hchacha20_outputbytes() size_t {
	return C.crypto_core_hchacha20_outputbytes()
}

fn C.crypto_core_hchacha20_inputbytes() size_t

pub fn crypto_core_hchacha20_inputbytes() size_t {
	return C.crypto_core_hchacha20_inputbytes()
}

fn C.crypto_core_hchacha20_keybytes() size_t

pub fn crypto_core_hchacha20_keybytes() size_t {
	return C.crypto_core_hchacha20_keybytes()
}

fn C.crypto_core_hchacha20_constbytes() size_t

pub fn crypto_core_hchacha20_constbytes() size_t {
	return C.crypto_core_hchacha20_constbytes()
}

fn C.crypto_core_hsalsa20(out &byte, in_ &byte, k &byte, c &byte) int

pub fn crypto_core_hsalsa20(out &byte, in_ &byte, k &byte, c &byte) int {
	return C.crypto_core_hsalsa20(out, in_, k, c)
}

fn C.crypto_core_ed25519_is_valid_point(p &byte) int

pub fn crypto_core_ed25519_is_valid_point(p &byte) int {
	return C.crypto_core_ed25519_is_valid_point(p)
}

fn C.crypto_core_ed25519_add(r &byte, p &byte, q &byte) int

pub fn crypto_core_ed25519_add(r &byte, p &byte, q &byte) int {
	return C.crypto_core_ed25519_add(r, p, q)
}

fn C.crypto_core_ed25519_sub(r &byte, p &byte, q &byte) int

pub fn crypto_core_ed25519_sub(r &byte, p &byte, q &byte) int {
	return C.crypto_core_ed25519_sub(r, p, q)
}

fn C.crypto_core_ed25519_from_uniform(p &byte, r &byte) int

pub fn crypto_core_ed25519_from_uniform(p &byte, r &byte) int {
	return C.crypto_core_ed25519_from_uniform(p, r)
}

fn C.crypto_core_ed25519_random(p &byte) 

pub fn crypto_core_ed25519_random(p &byte)  {
	C.crypto_core_ed25519_random(p)
}

fn C.crypto_core_ed25519_scalar_random(r &byte) 

pub fn crypto_core_ed25519_scalar_random(r &byte)  {
	C.crypto_core_ed25519_scalar_random(r)
}

fn C.crypto_core_ed25519_scalar_invert(recip &byte, s &byte) int

pub fn crypto_core_ed25519_scalar_invert(recip &byte, s &byte) int {
	return C.crypto_core_ed25519_scalar_invert(recip, s)
}

fn C.crypto_core_ed25519_scalar_negate(neg &byte, s &byte) 

pub fn crypto_core_ed25519_scalar_negate(neg &byte, s &byte)  {
	C.crypto_core_ed25519_scalar_negate(neg, s)
}

fn C.crypto_core_ed25519_scalar_complement(comp &byte, s &byte) 

pub fn crypto_core_ed25519_scalar_complement(comp &byte, s &byte)  {
	C.crypto_core_ed25519_scalar_complement(comp, s)
}

fn C.crypto_core_ed25519_scalar_add(z &byte, x &byte, y &byte) 

pub fn crypto_core_ed25519_scalar_add(z &byte, x &byte, y &byte)  {
	C.crypto_core_ed25519_scalar_add(z, x, y)
}

fn C.crypto_core_ed25519_scalar_sub(z &byte, x &byte, y &byte) 

pub fn crypto_core_ed25519_scalar_sub(z &byte, x &byte, y &byte)  {
	C.crypto_core_ed25519_scalar_sub(z, x, y)
}

fn C.crypto_core_ed25519_scalar_mul(z &byte, x &byte, y &byte) 

pub fn crypto_core_ed25519_scalar_mul(z &byte, x &byte, y &byte)  {
	C.crypto_core_ed25519_scalar_mul(z, x, y)
}

fn C.crypto_core_ed25519_scalar_is_canonical(s &byte) int

pub fn crypto_core_ed25519_scalar_is_canonical(s &byte) int {
	return C.crypto_core_ed25519_scalar_is_canonical(s)
}

fn C.crypto_core_ed25519_bytes() size_t

pub fn crypto_core_ed25519_bytes() size_t {
	return C.crypto_core_ed25519_bytes()
}

fn C.crypto_core_ed25519_nonreducedscalarbytes() size_t

pub fn crypto_core_ed25519_nonreducedscalarbytes() size_t {
	return C.crypto_core_ed25519_nonreducedscalarbytes()
}

fn C.crypto_core_ed25519_uniformbytes() size_t

pub fn crypto_core_ed25519_uniformbytes() size_t {
	return C.crypto_core_ed25519_uniformbytes()
}

fn C.crypto_core_ed25519_hashbytes() size_t

pub fn crypto_core_ed25519_hashbytes() size_t {
	return C.crypto_core_ed25519_hashbytes()
}

fn C.crypto_core_ed25519_scalarbytes() size_t

pub fn crypto_core_ed25519_scalarbytes() size_t {
	return C.crypto_core_ed25519_scalarbytes()
}

fn C.crypto_core_ristretto255_is_valid_point(p &byte) int

pub fn crypto_core_ristretto255_is_valid_point(p &byte) int {
	return C.crypto_core_ristretto255_is_valid_point(p)
}

fn C.crypto_core_ristretto255_add(r &byte, p &byte, q &byte) int

pub fn crypto_core_ristretto255_add(r &byte, p &byte, q &byte) int {
	return C.crypto_core_ristretto255_add(r, p, q)
}

fn C.crypto_core_ristretto255_sub(r &byte, p &byte, q &byte) int

pub fn crypto_core_ristretto255_sub(r &byte, p &byte, q &byte) int {
	return C.crypto_core_ristretto255_sub(r, p, q)
}

fn C.crypto_core_ristretto255_from_hash(p &byte, r &byte) int

pub fn crypto_core_ristretto255_from_hash(p &byte, r &byte) int {
	return C.crypto_core_ristretto255_from_hash(p, r)
}

fn C.crypto_core_ristretto255_random(p &byte) 

pub fn crypto_core_ristretto255_random(p &byte)  {
	C.crypto_core_ristretto255_random(p)
}

fn C.crypto_core_ristretto255_scalar_random(r &byte) 

pub fn crypto_core_ristretto255_scalar_random(r &byte)  {
	C.crypto_core_ristretto255_scalar_random(r)
}

fn C.crypto_core_ristretto255_scalar_invert(recip &byte, s &byte) int

pub fn crypto_core_ristretto255_scalar_invert(recip &byte, s &byte) int {
	return C.crypto_core_ristretto255_scalar_invert(recip, s)
}

fn C.crypto_core_ristretto255_scalar_negate(neg &byte, s &byte) 

pub fn crypto_core_ristretto255_scalar_negate(neg &byte, s &byte)  {
	C.crypto_core_ristretto255_scalar_negate(neg, s)
}

fn C.crypto_core_ristretto255_scalar_complement(comp &byte, s &byte) 

pub fn crypto_core_ristretto255_scalar_complement(comp &byte, s &byte)  {
	C.crypto_core_ristretto255_scalar_complement(comp, s)
}

fn C.crypto_core_ristretto255_scalar_add(z &byte, x &byte, y &byte) 

pub fn crypto_core_ristretto255_scalar_add(z &byte, x &byte, y &byte)  {
	C.crypto_core_ristretto255_scalar_add(z, x, y)
}

fn C.crypto_core_ristretto255_scalar_sub(z &byte, x &byte, y &byte) 

pub fn crypto_core_ristretto255_scalar_sub(z &byte, x &byte, y &byte)  {
	C.crypto_core_ristretto255_scalar_sub(z, x, y)
}

fn C.crypto_core_ristretto255_scalar_mul(z &byte, x &byte, y &byte) 

pub fn crypto_core_ristretto255_scalar_mul(z &byte, x &byte, y &byte)  {
	C.crypto_core_ristretto255_scalar_mul(z, x, y)
}

fn C.crypto_core_ristretto255_scalar_reduce(r &byte, s &byte) 

pub fn crypto_core_ristretto255_scalar_reduce(r &byte, s &byte)  {
	C.crypto_core_ristretto255_scalar_reduce(r, s)
}

fn C.crypto_core_ristretto255_scalar_is_canonical(s &byte) int

pub fn crypto_core_ristretto255_scalar_is_canonical(s &byte) int {
	return C.crypto_core_ristretto255_scalar_is_canonical(s)
}

fn C.load_3(in_ &byte) u64

pub fn load_3(in_ &byte) u64 {
	return C.load_3(in_)
}

fn C.load_4(in_ &byte) u64

pub fn load_4(in_ &byte) u64 {
	return C.load_4(in_)
}

fn C.slide_vartime(r &byte, a &byte) 

pub fn slide_vartime(r &byte, a &byte)  {
	C.slide_vartime(r, a)
}

fn C.equal(b byte, c byte) byte

pub fn equal(b byte, c byte) byte {
	return C.equal(b, c)
}

fn C.negative(b byte) byte

pub fn negative(b byte) byte {
	return C.negative(b)
}

fn C.ge25519_is_canonical(s &byte) int

pub fn ge25519_is_canonical(s &byte) int {
	return C.ge25519_is_canonical(s)
}

fn C.ge25519_has_small_order(s &byte) int

pub fn ge25519_has_small_order(s &byte) int {
	return C.ge25519_has_small_order(s)
}

fn C.sc25519_mul(s &byte, a &byte, b &byte) 

pub fn sc25519_mul(s &byte, a &byte, b &byte)  {
	C.sc25519_mul(s, a, b)
}

fn C.sc25519_muladd(s &byte, a &byte, b &byte, c &byte) 

pub fn sc25519_muladd(s &byte, a &byte, b &byte, c &byte)  {
	C.sc25519_muladd(s, a, b, c)
}

fn C.sc25519_sq(s &byte, a &byte) 

pub fn sc25519_sq(s &byte, a &byte)  {
	C.sc25519_sq(s, a)
}

fn C.sc25519_sqmul(s &byte, n int, a &byte) 

pub fn sc25519_sqmul(s &byte, n int, a &byte)  {
	C.sc25519_sqmul(s, n, a)
}

fn C.sc25519_invert(recip &byte, s &byte) 

pub fn sc25519_invert(recip &byte, s &byte)  {
	C.sc25519_invert(recip, s)
}

fn C.sc25519_reduce(s &byte) 

pub fn sc25519_reduce(s &byte)  {
	C.sc25519_reduce(s)
}

fn C.sc25519_is_canonical(s &byte) int

pub fn sc25519_is_canonical(s &byte) int {
	return C.sc25519_is_canonical(s)
}

fn C.ge25519_from_uniform(s &byte, r &byte) 

pub fn ge25519_from_uniform(s &byte, r &byte)  {
	C.ge25519_from_uniform(s, r)
}

fn C.ge25519_from_hash(s &byte, h &byte) 

pub fn ge25519_from_hash(s &byte, h &byte)  {
	C.ge25519_from_hash(s, h)
}

fn C.ristretto255_is_canonical(s &byte) int

pub fn ristretto255_is_canonical(s &byte) int {
	return C.ristretto255_is_canonical(s)
}

fn C.ristretto255_from_hash(s &byte, h &byte) 

pub fn ristretto255_from_hash(s &byte, h &byte)  {
	C.ristretto255_from_hash(s, h)
}

