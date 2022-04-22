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
 template <typename T>
void print_hex(T buffer);


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


/**
 * Splits an input string by a delimiter.
 *
 * NOTE: If the input string does not have a occurrence of delim in it, the entire
 * string is returned as the only instance in the vector.
 *
 * This was created for level 13, but is generically useful.
 *
 * @param input - The input string
 * @param delim - The delimiter to search for
 *
 * @return a vector of strings. This will be empty if there if no delimited strings are found.
 */
vector<std::string> split_by_delimiter(const std::string& input, char delim);


/**
 * Get a key value pair.
 *
 * Takes the string "key=value" as input, and returns a pair object of where "first" is
 * the key and "second" is the value.
 *
 * This was created for level 13, but could be generically useful.
 *
 * @param kv_str - The key value string.
 * @return A pair object with the key and value split out.
 */
std::pair<std::string, std::string> get_key_value(const std::string& kv_str);



#endif //CRYPTOPALS_HELPERS_HPP
