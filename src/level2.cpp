//
// Created by jordan on 1/28/22.
//

#include <iostream>
#include <string>
using std::string;
#include <vector>
using std::vector;
#include "xor.hpp"
#include "helpers.hpp"
#include "cryptvec.h"

int main() {
    vector<uint8_t> soltuion = { 0x74, 0x68, 0x65, 0x20, 0x6b, 0x69, 0x64, 0x20, 0x64, 0x6f, 0x6e, 0x27, 0x74, 0x20, 0x70, 0x6c,
                                 0x61, 0x79 };

    cryptvec a(hex_str_to_bytes("1c0111001f010100061a024b53535009181c"));
    cryptvec b(hex_str_to_bytes("686974207468652062756c6c277320657965"));

    //vector<uint8_t> result = vector_xor(a, b);
    a ^= b;
    print_hex(a);

    return 0;
}
