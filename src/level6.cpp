/**
 * Break multibyte XOR "encryption".
 */
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include "helpers.hpp"
#include "xor.hpp"
#include "file_ops.h"
#include "base64.h"
#include "ascii_analysis.h"
#include "hamming.h"

int main()
{
    std::string a("this is a test");
    std::string b("wokka wokka!!!");

    cryptvec a_bytes(a);
    cryptvec b_bytes(b);

    //int distance = calc_hamming_distance(a_bytes, b_bytes);
    auto distance = a_bytes.distance(b_bytes);
    std::cout << "Distance: " << distance << std::endl;

    // Read in our file.
    std::string file_data = read_entire_file("../data/level6_data.txt");
    file_data.erase(std::remove(file_data.begin(), file_data.end(), '\n'), file_data.end());

    int space_needed = Base64decode_len(file_data.data());
    std::cout << "Needed " << space_needed << " bytes" << std::endl;
    vector<uint8_t> ct(space_needed);
    Base64decode(reinterpret_cast<char*>(ct.data()), file_data.data());

    print_hex(ct);
    vector<key_length_t> key_lengths = find_key_size(ct, 2, 41, 10);
    for (auto & key_length : key_lengths)
    {
        std::cout << "Length - " << key_length.length << " distance - " << key_length.normalized_distance << std::endl;
    }

    vector<vector<uint8_t>> candidate_keys = bruteforce_multibyte_xor(ct, key_lengths);
    for (const vector<uint8_t>& key : candidate_keys)
    {
        string string_key { key.begin(), key.end() };
        std::cout << string_key << std::endl;
    }

    vector<uint8_t> pt = multi_byte_xor(ct, candidate_keys[1]);
    std::string pt_string = {pt.begin(), pt.end()};
    std::cout << pt_string << std::endl;

}