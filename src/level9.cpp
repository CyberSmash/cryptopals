/**
 * Simply implement PKCS#7 padding scheme.
 */
#include <vector>
#include <string>

#include "aes.h"
#include "cryptvec.h"
#include "helpers.hpp"

int main()
{
    std::string to_encode = "YELLOW SUBMARINE";
    vector<uint8_t> vec = {to_encode.begin(), to_encode.end()};

    pad_pkcs7(vec, 20);

    print_hex(vec);

    return 0;
}