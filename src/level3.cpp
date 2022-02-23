#include <vector>
using std::vector;
#include <iostream>
#include <iomanip>
#include <cstdint>
#include "ascii_analysis.h"
#include "helpers.hpp"
#include <algorithm>
int main() {

    cryptvec input(hex_str_to_bytes("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"));

    vector<key_score_t> all_scores = calculate_scores(input);
    std::sort(all_scores.begin(), all_scores.end(), [](const key_score_t& a, const key_score_t& b) {
        return a.score > b.score;
    });

    for (auto score : all_scores)
    {
        if (score.score > 1)
        {
            std::cout << "Key: " << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(score.key) << std::dec
                      << " - score: " << score.score << "result: " << vector_to_string(score.result) << std::endl;
            std::cout << "Relative Occurrances: " << calculate_relative_frequencies(score.result) << std::endl;
        }

    }

    return 0;
}