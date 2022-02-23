#include <stdexcept>
#include "xor.hpp"
#include "hamming.h"
#include <algorithm>
#include <iostream>


vector<uint8_t> vector_xor(vector<uint8_t> a, vector<uint8_t> b)
{
    vector<uint8_t> result;

    if (a.size() != b.size())
    {
        throw std::invalid_argument("The two provided vectors are not the same size.");
    }

    result.resize(a.size());

    for (int i = 0; i < a.size(); i++) {
        result[i] = a[i] ^ b[i];
    }

    return result;
}

vector<uint8_t> single_byte_xor(const vector<uint8_t>& vec, uint8_t byte) {
    vector<uint8_t> res(vec.size());

    std::transform(vec.begin(), vec.end(), res.begin(),
                   [byte](uint8_t v) -> uint8_t { return v ^ byte; });

    return res;
}

vector<uint8_t> multi_byte_xor(vector<uint8_t> pt, vector<uint8_t> key)
{
    size_t key_index = 0;
    vector<uint8_t> ct(pt.size());

    for (int i = 0; i < pt.size(); i++)
    {
        ct[i] = pt[i] ^ key[key_index];
        key_index = (key_index + 1) % key.size();
    }

    return ct;
}

vector<key_length_t> find_key_size(vector<uint8_t> ct, int length_min, int length_max, int num_results)
{
    vector<key_length_t> results;
    int slice_multiplier = 2;
    for (int current_key_length = length_min; current_key_length < length_max; current_key_length++)
    {
        // Get the first length of bytes
        if (current_key_length * 2 > ct.size())
        {
            std::cout << "Exhausted the largest proper key length based on the size of the cipher text. Aborting." << std::endl;
            break;
        }


        vector<uint8_t> first_chunk(ct.begin(), ct.begin() + current_key_length * slice_multiplier);
        vector<uint8_t> second_chunk(ct.begin() + current_key_length * slice_multiplier, ct.begin() + (current_key_length * slice_multiplier) * 2);

        int distance = calc_hamming_distance(first_chunk, second_chunk);
        key_length_t tmp = {
                .length = current_key_length,
                .hamming_distance = distance,
                .normalized_distance = static_cast<double>(distance) / static_cast<double>(current_key_length),
        };
        results.push_back(tmp);

    }

    // Now we have the lengths and hamming distancs, sort them.
    std::sort(results.begin(), results.end(), [](const key_length_t a, const key_length_t b)
    {
       return a.normalized_distance < b.normalized_distance;
    });
    if (num_results == -1)
    {
        return results;
    }
    return vector<key_length_t>(results.begin(), results.begin() + num_results);

}

vector<vector<uint8_t>> xor_reorder_blocks(vector<uint8_t> ct, int key_length)
{
    vector<vector<uint8_t>> t(key_length);

    for (int i = 0; i < ct.size(); i++)
    {
        int block = i % key_length;
        t[block].push_back(ct[i]);
    }

    return t;
}



