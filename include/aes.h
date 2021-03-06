#ifndef _AES_H
#define _AES_H

#include <cstdint>
#include <vector>
using std::vector;
#include "cryptvec.h"
#define AES_BLOCK_SIZE 16

/**
 * Decrypts data given by ct with key using the AES algorithm.
 *
 * @TODO: This is technically only AES128, meaning we should
 * label it as such.
 *
 * @TODO: This function performs no error checking. It would be a good idea
 * to implement it.
 *
 * @param key The AES key. Must be 16 bytes long.
 * @param ct The cipher text. Must be a muiltiple of
 * @return The decrypted ciphertext.
 */
template <typename T>
T aes_decrypt_ecb(T key, T ct);

/**
 * Encrypt data using AES-128 in ECB Mode.
 * @tparam T Either a vector or cryptvec.
 * @param key A key to encrypt with
 * @param pt The plaintext
 * @param add_padding If true, we will automatically add padding. If false, padding will not be added, but
 * you will be responsible for ensuring that the data is exactly a multiple of AES_BLOCK_SIZE (16 bytes).
 * @return The encrypted data.
 */
template <typename T>
T aes_encrypt_ecb(T key, T pt, bool add_padding=true);

/**
 * Encrypt data using AES-128 in CBC mode.
 * @param iv The initialization vector. Padding will be added using PKCS#7
 * @param key The key.
 * @param pt The plaintext
 * @return The encrypted ciphertext.
 */
cryptvec aes_encrypt_cbc(const cryptvec& iv, const cryptvec& key, cryptvec pt);

/**
 * Decrypt data using AES-128 CBC mode
 *
 * TODO: Padding is not currently removed.
 *
 * @param iv The initialization vector.
 * @param key The key
 * @param ct The cipher text to decrypt.
 * @return The plaintext.
 */
cryptvec aes_decrypt_cbc(const cryptvec& iv, const cryptvec& key, cryptvec ct);


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

/**
 * Finds the start of a adjacent repeating blocks of ciphertext.
 *
 * This is similar to is_ecb except that it will return the location of the first repated block and will
 * only look for adjacent blocks.
 *
 * @tparam T A type of either cryptvec or vector<uint8_t>.
 * @param arr A iteratble array containing ciphertext.
 * @return -1 if there is no repeating blocks adjacent. The start index of the first repeated block if a repeated block
 * exists.
 */
template <typename T>
int find_ecb(T arr);

/**
 * Pad the data out to a block_size.
 * @tparam T Some sort of iterable, like a cryptvec, or vector.
 * @param arr The array to add.
 * @param block_size The block size. Generally this will be AES_BLOCK_SIZE.
 * @return The number of bytes added.
 */
template <typename T>
unsigned int pad_pkcs7(T& arr, unsigned int block_size);

/**
 * Validates PKCS7 and returns the number of padding bytes to be removed.
 * @tparam T A cryptvec or vector<uint8_t>
 * @param arr The data to have the padding removed.
 * @param block_size The block size.
 * @return The number of padding bytes to be removed.
 */
template <typename T>
unsigned int validate_pkcs7(const T& arr, unsigned int block_size);

template <typename T>
T remove_pkcs7_padding(const T& arr, unsigned int max_block_size=AES_BLOCK_SIZE);

/**
 * Generate a cryptographically secure key.
 * @tparam T Either a vector or cryptvec
 * @param bytes The number of bytes you want
 * @return A type T containing the bytes you want.
 */
template <typename T>
T gen_random_key(unsigned int bytes);

#endif