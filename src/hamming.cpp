//
// Created by Jordan Sebastian on 2/16/22.
//

#include <iostream>
#include <algorithm>
#include "xor.hpp"
#include <stdexcept>
#include "hamming.h"
#include "cryptvec.h"

short int hamming_distance[] {
    0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8,
};

template <typename T, typename T2>
int calc_hamming_distance(T a, T2 b)
{
    int distance = 0;
    if (a.size() != b.size())
    {
        throw std::logic_error("Error: Both a and b must be equal length to calculate hamming distance.");
    }

    for (int i = 0; i < a.size(); i++)
    {
        distance += hamming_distance[a[i] ^ b[i]];
    }
    return distance;

}

template int calc_hamming_distance(vector<uint8_t> a, vector<uint8_t> b);
template int calc_hamming_distance(cryptvec a, cryptvec b);
template int calc_hamming_distance(cryptvec a, vector<uint8_t> b);
template int calc_hamming_distance(vector<uint8_t> a, cryptvec b);
template int calc_hamming_distance(cryptvec a, std::string b);
template int calc_hamming_distance(std::string a, cryptvec b);
