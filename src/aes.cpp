#include "aes.h"
#include <openssl/evp.h>
#include <iostream>
#include <algorithm>
#include "cryptvec.h"
template <typename T, typename T2>
vector<uint8_t> aes_decrypt_ecb(T key, T2 ct)
{

    auto decrypted = new uint8_t[ct.size()]();
    std::cout << "Reserving " << ct.size() << " bytes" << std::endl;
    int decrypted_len = 0;
    int len = 0;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit(ctx, EVP_aes_128_ecb(), reinterpret_cast<const unsigned char*>(key.data()), nullptr);

    EVP_DecryptUpdate(ctx, decrypted, &len, ct.data(), ct.size());
    decrypted_len += len;
    std::cout << "bytes read: " << decrypted_len << std::endl;
    EVP_DecryptFinal(ctx, decrypted+len, &len);
    decrypted_len += len;

    std::cout << "final bytes read: " << len << std::endl;

    EVP_CIPHER_CTX_free(ctx);


    vector<uint8_t> ret = { decrypted, decrypted + decrypted_len};
    delete[] decrypted;
    return ret;
}

template <typename T>
bool is_ecb(T arr)
{
    // We need to have at least two blocks to identify AES in ECB mode.
    if (arr.size() <= AES_BLOCK_SIZE * 2)
        return false;
    // We need to be a multiple of block size.
    if (arr.size() % 16 != 0)
        return false;

    int num_blocks = arr.size() / AES_BLOCK_SIZE;

    // This isn't the most efficient thing to do, but it might just be the easiest to write.
    vector<T> all_blocks;
    for (auto it = arr.begin(); it != arr.end(); it += AES_BLOCK_SIZE)
    {
        all_blocks.push_back({it, it + AES_BLOCK_SIZE});
    }


    for (auto needle_block = all_blocks.begin(); needle_block != all_blocks.end() - 1; needle_block++)
    {
        for (auto search_block = needle_block + 1; search_block != all_blocks.end(); search_block++)
        {
            bool found = std::equal((*needle_block).begin(), (*needle_block).end(), (*search_block).begin(), (*search_block).end());
            if (found)
                return true;
        }
    }

    return false;
}

template vector<uint8_t> aes_decrypt_ecb(vector<uint8_t> key, vector<uint8_t> ct);
template vector<uint8_t> aes_decrypt_ecb(std::string key, vector<uint8_t> ct);

template bool is_ecb(std::vector<uint8_t> arr);
template bool is_ecb(cryptvec);
//template bool is_ecb(cryptvec arr);