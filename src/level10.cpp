/**
 * Encrypt and decrypt using AES-128 in CBC mode.
 */

#include <iostream>
#include <algorithm>
#include "aes.h"
#include "helpers.hpp"
#include "cryptvec.h"
#include "file_ops.h"

int main()
{
    std::string key("YELLOW SUBMARINE");
    // Decrypt the data.
    vector<uint8_t> file_data = read_base64_decode("../data/level7_data.txt");
    vector<uint8_t> pt = aes_decrypt_ecb({key.begin(), key.end()}, file_data);
    for (char c : pt)
        std::cout << c;
    std::cout << std::endl;

    // Re-encrypt the data.
    vector<uint8_t> ct = aes_encrypt_ecb({key.begin(), key.end()}, pt);

    std::cout << "Original file data size: " << file_data.size() << std::endl;
    std::cout << "New cipher text data size: " << ct.size() << std::endl;

    // This line secretly ignores the padding bytes, as we base the size to check off of file_data
    bool eq = std::equal(file_data.begin(), file_data.end(), ct.begin());
    if (eq)
        std::cout << "The data matches. ECB encryption is good to go." << std::endl;
    else
        std::cout << "The data does not match." << std::endl;

    cryptvec iv = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    cryptvec pt2 = {0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41};

    cryptvec ct2 = aes_encrypt_cbc(iv, {key.begin(), key.end()},pt2);
    print_hex(ct2);

    std::cout << "Decrypting." << std::endl;
    cryptvec pt3 = aes_decrypt_cbc(iv, {key.begin(), key.end()}, ct2);
    std::cout << pt3 << std::endl;

    return 0;
}