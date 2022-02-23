#include <iostream>
#include <string>
#include <cstring>

using std::string;

#include "helpers.hpp"

int main() {
    string hex_str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    string solution = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    vector<uint8_t> vec = hex_str_to_bytes(hex_str);
    int strncmp_result = 0;
    print_hex(vec);

    char* b64 = hex_bytes_to_base64(vec);

    std::cout << b64 << std::endl;

    strncmp_result = std::strncmp(solution.c_str(), b64, solution.length());
    if (strncmp_result == 0)
    {
        std::cout << "PASS!" << std::endl;
    }
    else
    {
        std::cout << "FAIL" << std::endl;
    }

    delete[] b64;
    return 0;
}
