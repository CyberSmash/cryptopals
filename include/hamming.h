//
// Created by Jordan Sebastian on 2/16/22.
//

#ifndef CRYPTOPALS_HAMMING_H
#define CRYPTOPALS_HAMMING_H

/**
 * Calculate the hamming distance of two equal length vectors.
 *
 * @param a - The first vector.
 * @param b - The second vector
 * @return The hamming/edit distance
 *
 * @throws invalid_parameter if a and b are not the same length.
 */

template <typename T, typename T2>
int calc_hamming_distance(T a, T2 b);

#include <cstdint>
#include <vector>

#endif //CRYPTOPALS_HAMMING_H
