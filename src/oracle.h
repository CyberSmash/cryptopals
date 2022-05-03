#ifndef CRYPTOPALS_ORACLE_H
#define CRYPTOPALS_ORACLE_H
#include "cryptvec.h"
#include "base64.h"
#include <map>
/**
 * Creates an encryption oracle for level 12.
 *
 * This is created specifically for Challenge 11, in creating code that detects
 * ecb or cbc mode.
 *
 * This will add some number of bytes of padding (5-10 bytes) to the front and back
 * of the plaintext, and will also randomly choose between CBC and ECB mode.
 *
 * It will also pick a random key and a random IV (in the case of CBC mode.
 *
 * @param pt The plaintext to encrypt
 * @param is_ecb Whether or not this is ECB. We will use this to check our final answers once
 * we think we have solved the problem.
 * @return The ciphertext.
 */
cryptvec level11_encryption_oracle(const cryptvec& pt, bool& is_ecb);


/**
 * Creates an encryption oracle for level 12.
 *
 * This encryption is specifically for level 12. This will append some (unknown) data
 * to the end of the plaintext and encrypt with a static but unknown and random key.
 *
 * @param pt The plaintext passed in to encrypt.
 * @return A buffer of ciphertext.
 */
cryptvec level12_encryption_oracle(const cryptvec& pt, const cryptvec& prefix);

/**
 * Breaks an ECB Oracle where some secret data is added to the end of the provided plaintext
 *
 * This is written to solve problem #12, but is pretty generic to any cipher oracle
 * that appends secret data to the end of a provided plaintext and is in ECB mode.
 *
 * Additionally it must reuse the same key every time.
 *
 * @param block_size The block size of the cipher.
 * @param num_secret_blocks The total number of blocks that make up the secret.
 * @param num_pad_bytes The number of padding bytes added to the secret.
 * @return A cryptvec that contains the secret data that was appended to the plaintext.
 */
cryptvec break_level12_ecb_oracle(unsigned int block_size,    unsigned int num_secret_blocks,
                                  unsigned int num_pad_bytes);

/**
 * Finds a single byte in the level12 ecb oracle breaker.
 *
 * This is used by break_level12_ecb_oracle. It is the core of finding a single byte.
 *
 * test_pt shoud have the following format [filler][known bytes][single empty byte].
 *
 * @param expected_ct The cipher text block we are ultimately searching for.
 * @param test_pt The plaintext that contais all filler and already broken bytes. It should be the size of a block,
 * but the last byte wont' matter as it will be replaced.
 * @param ct_offset An offset into the cipher text so we know what block we should be looking at.
 * @return The correct byte that causes test_pt to match expected_ct.
 * @throws logic_error if a byte that works for the block is not found.
 */
uint8_t break_level12_single_byte_oracle(const cryptvec& expected_ct, cryptvec test_pt, unsigned int ct_offset);

/**
 * Parses a key=value string delimited by an '&'.
 *
 * This was created for level 13.
 *
 * Example "foo=bar&baz=qux&zap=zazzle"
 *
 * @param kv_string The string to parse.
 * @return A dictionary where the first is the key and second is the value all represented by strings.
 */
//std::map<std::string, std::string> level13_parse_kv_string(const std::string& kv_string);

/**
 * Generates a key value string based on a map.
 *
 * TODO: We don't check for fields, but we should.
 *
 * Expected fields: "role", "email", and "uid".
 *
 * @param profile The profile map to use.
 * @return
 */
//std::string level13_encode_profile(std::map<std::string, std::string>& profile);


#endif //CRYPTOPALS_ORACLE_H
