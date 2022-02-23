/**
 * A catch all for various helper functions, generally for
 * encoding and decoding.
 */
#ifndef CRYPTOPALS_HELPERS_HPP
#define CRYPTOPALS_HELPERS_HPP
#include <string>

#include <vector>
using std::vector;

/**
 * Convert a single hex-compatible character to it's 4-bit hex equivalent.
 * @param c - The character to convert to a 4-bit byte.
 *
 * @return The 4-bit integer value of the hex string.
 * @throws std::invalid_parameter if the character is not a valid hex byte.
 */
uint8_t hex_char_to_byte(char c);


/**
 * Convert a string of hex characters to a vector of bytes.
 *
 * Note: this function does not trim any characters, and expects bytes to not be
 * separated by any delimiter.
 *
 * @param hex_string A valid hex string
 * @return A vector containing the bytes.
 * @throws std::invalid_parameter from hex_char_to_byte if an invalid character is encountered.
 * @throws std::invalid_parameter if the provided hex_string paramter is an uneven number of characters.
 */
vector<uint8_t> hex_str_to_bytes(const std::string& hex_string);


/**
 * Print the hex buffer.
 *
 * @param buffer - The buffer to print.
 */
void print_hex(vector<uint8_t> buffer);


/**
 * Convert a hex vector to a base64 C-style string.
 *
 * NOTE: This function allocates the buffer returned. The caller is responsible for
 * calling delete[].
 *
 * @param buffer - The buffer to convert.
 * @return A null terminated character string.
 */
char* hex_bytes_to_base64(vector<uint8_t> buffer);


std::string vector_to_string(vector<uint8_t> vec);

#endif //CRYPTOPALS_HELPERS_HPP
