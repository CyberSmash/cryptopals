//
// Created by jordan on 1/28/22.
//

#ifndef CRYPTOPALS_XOR_HPP
#define CRYPTOPALS_XOR_HPP
#include <cstdint>
#include <vector>
using std::vector;

typedef struct _key_length {
    int length;
    int hamming_distance;
    double normalized_distance;
} key_length_t;

/**
 * XOR two equal length vectors.
 *
 * @param a The first vector.
 * @param b The second vector.
 * @return A vector that is the byte-for-byte XOR of the two buffers.
 */
vector<uint8_t> vector_xor(vector<uint8_t> a, vector<uint8_t> b);

/**
 * XORs an entire vector by a single byte.
 *
 * @param vec - The vector to use
 * @param byte - The byte (key) to use.
 * @return A vector that has the same length as A but is vec ^ byte for the length of the vector.
 */
vector<uint8_t> single_byte_xor(const vector<uint8_t>& vec, uint8_t byte);

/**
 * Multibyte key XOR.
 *
 * @param pt - The plaintext
 * @param key - The key
 * @return The cipher text.
 */
vector<uint8_t> multi_byte_xor(vector<uint8_t> pt, vector<uint8_t> key);


/**
 * Find the most likely key lengths for the XOR ciphertext.
 *
 * @param ct The vector containing the multi-byte XOR cipher data
 * @param length_min The minimum key length to search for
 * @param length_max The maximum key length to search for
 * @param num_results The number of results to return in ascending order. If this is -1 all results are returned.
 * @return num_results number of results.
 */
vector<key_length_t> find_key_size(vector<uint8_t> ct, int length_min, int length_max, int num_results);

/**
 * Rearrange a repeataed key XOR'd cipher text so that
 * each 'block' would align to one byte of the key.
 *
 * @param ct - The cipher text
 * @param key_length - The key length.
 * @return A vector of vectors which should all be XOR'd by the same key if the
 * key length is correct.
 */
vector<vector<uint8_t>> xor_reorder_blocks(vector<uint8_t> ct, int key_length);


#endif //CRYPTOPALS_XOR_HPP
