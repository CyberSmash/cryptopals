#include "ascii_analysis.h"
#include "xor.hpp"
#include <algorithm>
#include <string>
#include <cctype>
#include "cryptvec.h"
char alphabet[] = "abcdefghijklmnopqrstuvwxyz";

double ascii_modifier = 1;
double letter_frequency_modifier = 0.01;

double letter_frequency[256] = {0.0};

bool frequencies_initialized = false;

/**
 * Found this trick somewhere on github. It's way better
 * than the old way I was doing it.
 */
void initialize_letter_frequencies()
{
    letter_frequency['a'] = 0.0834;
    letter_frequency['b'] = 0.0154;
    letter_frequency['c'] = 0.0273;
    letter_frequency['d'] = 0.0414;
    letter_frequency['e'] = 0.1260;
    letter_frequency['f'] = 0.0203;
    letter_frequency['g'] = 0.0192;
    letter_frequency['h'] = 0.0611;
    letter_frequency['i'] = 0.0671;
    letter_frequency['j'] = 0.0023;
    letter_frequency['k'] = 0.0087;
    letter_frequency['l'] = 0.0424;
    letter_frequency['m'] = 0.0253;
    letter_frequency['n'] = 0.0680;
    letter_frequency['o'] = 0.0770;
    letter_frequency['p'] = 0.0166;
    letter_frequency['q'] = 0.0009;
    letter_frequency['r'] = 0.0568;
    letter_frequency['s'] = 0.0611;
    letter_frequency['t'] = 0.0937;
    letter_frequency['u'] = 0.0285;
    letter_frequency['v'] = 0.0106;
    letter_frequency['w'] = 0.0234;
    letter_frequency['x'] = 0.0020;
    letter_frequency['y'] = 0.0204;
    letter_frequency['z'] = 0.0006;
    letter_frequency['A'] = 0.0834;
    letter_frequency['B'] = 0.0154;
    letter_frequency['C'] = 0.0273;
    letter_frequency['D'] = 0.0414;
    letter_frequency['E'] = 0.1260;
    letter_frequency['F'] = 0.0203;
    letter_frequency['G'] = 0.0192;
    letter_frequency['H'] = 0.0611;
    letter_frequency['I'] = 0.0671;
    letter_frequency['J'] = 0.0023;
    letter_frequency['K'] = 0.0087;
    letter_frequency['L'] = 0.0424;
    letter_frequency['M'] = 0.0253;
    letter_frequency['N'] = 0.0680;
    letter_frequency['O'] = 0.0770;
    letter_frequency['P'] = 0.0166;
    letter_frequency['Q'] = 0.0009;
    letter_frequency['R'] = 0.0568;
    letter_frequency['S'] = 0.0611;
    letter_frequency['T'] = 0.0937;
    letter_frequency['U'] = 0.0285;
    letter_frequency['V'] = 0.0106;
    letter_frequency['W'] = 0.0234;
    letter_frequency['X'] = 0.0020;
    letter_frequency['Y'] = 0.0204;
    letter_frequency['Z'] = 0.0006;
    // Uncomment if you think the data is textual,
    // This may heavily bias away from
    // keys that don't include spaces.
    letter_frequency[' '] = 0.2000;
}

double score_english_ascii(const vector<uint8_t>& vec)
{
    if (!frequencies_initialized)
    {
        initialize_letter_frequencies();
        frequencies_initialized = true;
    }

    double total_score = 0.0;
    for (auto character : vec)
    {
        if (character == '\r' || character == '\n')
            continue;

        // This shouldn't get any points for anything that isn't in the ASCII
        // range as we are looking for english text.
        if (character < 0x20 || character > 0x7e)
            return 0;
        total_score += letter_frequency[character];
    }

    return total_score;
}


std::string calculate_relative_frequencies(const vector<uint8_t>& vec)
{
    vector<letter_occurrence_t> frequencies(26);
    std::string ret = "";

    /**
     * Set up the vector
     */
    for (char c = 0; c < 26; c++)
    {
        frequencies[c].character = alphabet[c];
    }

    /**
     * Calculate how often each character shows up.
     */
    for (uint8_t val : vec)
    {
        if (isalpha(val))
        {
            char lower_val = tolower(val);
            frequencies[lower_val - 'a'].character = lower_val;
            frequencies[lower_val - 'a'].occurances += 1;
        }
    }

    std::sort(frequencies.begin(), frequencies.end(),
              [](const letter_occurrence_t& a, const letter_occurrence_t &b) {
                return a.occurances > b.occurances;
              });

    std::for_each(frequencies.begin(), frequencies.end(), [&ret](const letter_occurrence_t& occurrence) {
        if (occurrence.character != '\0')
            ret += occurrence.character;
    });

    return ret;
}

vector<key_score_t> calculate_scores(const vector<uint8_t>& ct)
{
    vector<key_score_t> scores(256);
    uint8_t current_key = 0x0;

    for (int i = 0; i < 256; i++, current_key++)
    {
        vector<uint8_t> result = single_byte_xor(ct, current_key);
        scores[i].result.resize(ct.size());
        scores[i].key = current_key;
        scores[i].score = score_english_ascii(result);
        scores[i].result = result;
    }

    return scores;
}

vector<key_score_t> calculate_scores(const cryptvec& ct)
{
    vector<key_score_t> scores(256);
    uint8_t current_key = 0x0;

    for (int i = 0; i < 256; i++, current_key++)
    {
        vector<uint8_t> result = ct ^ current_key;
        scores[i].result.resize(ct.size());
        scores[i].key = current_key;
        scores[i].score = score_english_ascii(result);
        scores[i].result = result;
    }

    return scores;
}

vector<key_score_t> calculate_scores(const vector<uint8_t>& ct, bool sort, int limit)
{
    vector<key_score_t> scores = calculate_scores(ct);
    if (sort)
    {
        std::sort(scores.begin(), scores.end(), [](const key_score_t& a, const key_score_t& b) {
            return a.score > b.score;
        });
    }

    if (limit > 0 && limit < ct.size())
    {
        return {scores.begin(), scores.begin() + limit};
    }
    return scores;
}

int get_best_score_index(const vector<key_score_t>& scores)
{
    int best = 0;
    int idx = -1;
    for (int i = 0; i < scores.size(); i++)
    {
        if (scores[i].score > best)
        {
            best = scores[i].score;
            idx = i;
        }
    }
    return idx;
}


vector<vector<uint8_t>> bruteforce_multibyte_xor(const vector<uint8_t>& ct,
                                                 const vector<key_length_t>& possible_key_lengths)
{

    vector<vector<uint8_t>> candidate_keys;
    for (const key_length_t& key_length : possible_key_lengths)
    {

        int length = key_length.length;
        // Re-arrange the cipertext into blocks so that each block contains only values that have been xor'd
        // with the same single byte of the key.
        vector<vector<uint8_t>> blocks = xor_reorder_blocks(ct, length);
        vector<uint8_t> current_key;
        for (const auto& block : blocks)
        {
            vector<key_score_t> scores = calculate_scores(block, true, 5);
            current_key.push_back(scores[0].key);
        }
        candidate_keys.push_back(current_key);
    }

    return candidate_keys;
}