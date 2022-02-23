#ifndef CRYPTOPALS_ASCII_ANALYSIS_H
#define CRYPTOPALS_ASCII_ANALYSIS_H

/**
 * A suite of tools for analyzing binary data for their relevance to US-ASCII and english.
 */

#include <vector>
using std::vector;

#include <cstdint>
#include <cctype>
#include <string>
#include "xor.hpp"
#include "cryptvec.h"

typedef struct key_score {
    uint8_t             key;
    vector<uint8_t>     result;
    double              score;
} key_score_t;

typedef struct _letter_occurrence {
    char character;
    int occurances;
} letter_occurrence_t;


extern char alphabet[];
extern char expected_frequency[];

/**
 * Create a score for how likely a vector is to be English text.
 *
 * NOTE: This takes into account two factors, first, whether or not the
 * text is printable, unprintable us-ascii characters are severely punished.
 *
 * The second thing is letter frequency. This is a function of where we expect
 * a letter to exist relative to all other letters used in the english language
 * compared to were they actually exist in the given text.
 *
 *
 * @param vec The vector of binary values to check.
 * @return A score from 0 - 1 indicating how likely the data is to be US-ASCII.
 * 1 is all printable characters 0 is no printable characters.
 */
double score_english_ascii(const vector<uint8_t>& vec);

/**
 * Get the relative frequency of printable characters in a vector.
 *
 * @param vec The vector to calculate
 * @return A vector with the characters sorted by frequency.
 */
std::string calculate_relative_frequencies(const vector<uint8_t>& vec);

/**
 * Gets the most likely single-byte XOR key for the provided ciphertext.
 *
 * NOTE: This is used for multi-byte and single-byte XOR breaking. For an example,
 * see bruteforce_multibyte_xor().
 *
 * @param ct The ciphertext block. This is expected to have been encrypted with only a single-byte key.
 *
 * @return A vector containing the scores for all possible keys.
 */
vector<key_score_t> calculate_scores(const vector<uint8_t>& ct);

/**
 * The same as the vectored version but with an easier data type to manage.
 * @param ct The ciphertext
 * @return A vector of scores.
 */
vector<key_score_t> calculate_scores(const cryptvec& ct);


/**
 * Gets the most likely single-byte XOR key for the provided ciphertext.
 * @param ct The ciphertext
 * @param sort Whether or not to sort the list of key scores. If true, the keys will be sorted. If false, they will not.
 * @param limit The number of keys we want returned. This will happen AFTER sorting.
 *
 * @return A vector of key scores, potentially sorted and limited.
 */
vector<key_score_t> calculate_scores(const vector<uint8_t>& ct, bool sort, int limit);



/**
 * Brute forces a multibyte XOR key.
 *
 * This will return a vector of the possible key candidates.
 *
 * @param ct The ciphertext
 * @param possible_key_lengths The possible key lengths. This is returned by the function
 * calc_hamming_distance().
 *
 * @return A vector containing the most likely keys.
 */
vector<vector<uint8_t>> bruteforce_multibyte_xor(const vector<uint8_t>& ct, const vector<key_length_t>& possible_key_lengths);

/**
 * Get the index in the scores vector of the best score.
 *
 * @param scores A vector containing key scores.
 * @return An index of the score in the vector with the best score.
 */
int get_best_score_index(const vector<key_score_t>& scores);


#endif //CRYPTOPALS_ASCII_ANALYSIS_H
