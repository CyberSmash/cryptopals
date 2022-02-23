//
// Created by jordan on 2/1/22.
//

#include <iostream>
#include <algorithm>

#include "helpers.hpp"
#include "file_ops.h"
#include "ascii_analysis.h"
int main()
{
    vector<string> all_lines = read_file_lines("../data/level4_data.txt");

    std::cout << "There are: " << all_lines.size() << " lines in the file." << std::endl;
    vector<key_score_t> best_scores;

    for (string line: all_lines)
    {
        // Convert to a byte array
        vector<uint8_t> bytes = hex_str_to_bytes(line);
        vector<key_score_t> scores = calculate_scores(bytes);

        int best_score = get_best_score_index(scores);
        best_scores.push_back(scores[best_score]);
    }

    std::sort(best_scores.begin(), best_scores.end(), [](const key_score_t& a, const key_score_t& b) {
        return a.score > b.score;
    });

    std::cout << "Most likely solution: " << vector_to_string(best_scores[0].result) << std::endl;

    return 0;

}