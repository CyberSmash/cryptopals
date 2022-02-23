#include <iostream>
#include "file_ops.h"
#include <vector>
#include <openssl/evp.h>
#include "aes.h"
int main ()
{
    std::vector<uint8_t> ct = read_base64_decode("../data/level7_data.txt");
    std::cout << "The number of bytes in the file are: " << ct.size() << std::endl;
    std::string key = "YELLOW SUBMARINE";

    auto decrypted_data = aes_decrypt_ecb(key, ct);

    for (char c : decrypted_data)
    {
        std::cout << c;
    }

    return 0;
}