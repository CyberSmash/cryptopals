#ifndef _AES_H
#define _AES_H

#include <cstdint>
#include <vector>
using std::vector;

#define AES_BLOCK_SIZE 16

/**
 * Decrypts data given by ct with key using the AES algorithm.
 *
 * @TOOD: This is technically only AES128, meaning we should
 * label it as such.
 *
 * @param key The AES key. Must be 16 bytes long.
 * @param ct The cipher text. Must be a muiltiple of
 * @return The decrypted ciphertext.
 */
template <typename T, typename T2>
vector<uint8_t> aes_decrypt_ecb(T key, T2 ct);

/**
 * Checks for an array of data to be AES in ECB mode.
 *
 * Note, this just determines if we see any 16 byte block repeat inside of itself.
 *
 * @tparam T Anything we can iterate over. Either a cryptvec, vector<uint8_t> or string.
 * @param arr The The array to search. Must be at least two AES block sizes long (32 bytes).
 * @return True if this array has a repeating block, and "is aes in ECB mode.". Returns False if it is not found,
 * or if there are invalid parameters.
 */
template <typename T>
bool is_ecb(T arr);

#endif