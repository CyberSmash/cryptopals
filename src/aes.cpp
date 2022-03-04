#include <openssl/evp.h>
#include <openssl/rand.h>
#include "aes.h"
#include <iostream>
#include <algorithm>
#include "cryptvec.h"
template <typename T>

T aes_decrypt_ecb(T key, T ct)
{

    auto            decrypted       = new uint8_t[ct.size()]();
    int             decrypted_len   = 0;
    int             len             = 0;
    EVP_CIPHER_CTX* ctx             = EVP_CIPHER_CTX_new();


    EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, reinterpret_cast<const unsigned char*>(key.data()), nullptr);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_DecryptUpdate(ctx, decrypted, &len, ct.data(), ct.size());
    decrypted_len += len;
    EVP_DecryptFinal(ctx, decrypted+len, &len);
    decrypted_len += len;
    EVP_CIPHER_CTX_free(ctx);


    T ret = { decrypted, decrypted + decrypted_len};
    delete[] decrypted;
    return ret;
}

template <typename T>
T aes_encrypt_ecb(T key, T pt, bool add_padding)
{
    int     buffer_size     = pt.size();
    int     padding_size    = AES_BLOCK_SIZE - (buffer_size % AES_BLOCK_SIZE);
    auto    buffer          = new uint8_t[buffer_size + padding_size]{};
    int     bytes_written   = 0;
    int     decrypted_len   = 0;
    auto    pt_ptr          = reinterpret_cast<const uint8_t*>(pt.data());

    // Create the context
    // TODO: This may be deprecated? *sigh* OpenSSL...
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    // Initialize.
    EVP_EncryptInit(ctx, EVP_aes_128_ecb(), reinterpret_cast<const unsigned char*>(key.data()), nullptr);
    if (!add_padding)
        EVP_CIPHER_CTX_set_padding(ctx, 0);

    EVP_EncryptUpdate(ctx,
                      buffer, &bytes_written,
                      pt_ptr, pt.size());
    decrypted_len += bytes_written;


    EVP_EncryptFinal(ctx, buffer+bytes_written, &bytes_written);

    EVP_CIPHER_CTX_free(ctx);

    decrypted_len += bytes_written;

    T encrypted = {buffer, buffer+decrypted_len};
    delete[] buffer;
    return encrypted;
}


cryptvec aes_encrypt_cbc(const cryptvec& iv, const cryptvec& key, cryptvec pt)
{
    cryptvec final_out {};
    // Pad out the plaintext.
    pad_pkcs7(pt, AES_BLOCK_SIZE);

    cryptvec new_iv = iv;

    for (auto block_it = pt.begin(); block_it != pt.end(); block_it += AES_BLOCK_SIZE)
    {
        cryptvec block = {block_it, block_it + AES_BLOCK_SIZE};
        block ^= new_iv;
        cryptvec encrypted_block = aes_encrypt_ecb(key, block, false);
        final_out.insert(final_out.end(), encrypted_block.begin(), encrypted_block.end());
        new_iv = encrypted_block;
    }

    return final_out;
}

cryptvec aes_decrypt_cbc(const cryptvec& iv, const cryptvec& key, cryptvec ct)
{
    cryptvec final_out {};

    cryptvec new_iv = iv;
    for (auto block_it = ct.begin(); block_it != ct.end(); block_it += AES_BLOCK_SIZE)
    {
        cryptvec block = {block_it, block_it + AES_BLOCK_SIZE};
        cryptvec pt_block = aes_decrypt_ecb(key, block);
        pt_block ^= new_iv;
        new_iv = block;
        final_out.insert(final_out.end(), pt_block.begin(), pt_block.end());
    }

    return final_out;
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

template <typename T>
unsigned int pad_pkcs7(T& arr, unsigned int block_size)
{
    uint8_t padding_needed = block_size - (arr.size() % block_size);
    for (int i = 0; i < padding_needed; i++)
    {
        arr.push_back(padding_needed);
    }

    return padding_needed;
}
template unsigned int pad_pkcs7(vector<uint8_t>& arr, unsigned int block_size);
template unsigned int pad_pkcs7(cryptvec& arr, unsigned int block_size);


template<typename T>
T gen_random_key(unsigned int bytes) {
    T key {};
    key.resize(bytes);
    int success = 0;
    do
    {
        success = RAND_bytes(key.data(), bytes);
    } while (success == 0);
    return key;
}

template vector<uint8_t> gen_random_key(unsigned int bytes);
template cryptvec gen_random_key(unsigned int bytes);


template vector<uint8_t> aes_decrypt_ecb(vector<uint8_t> key, vector<uint8_t> ct);
template cryptvec aes_decrypt_ecb(cryptvec key, cryptvec ct);

template vector<uint8_t> aes_encrypt_ecb(vector<uint8_t> key, vector<uint8_t> ct, bool add_padding);


template bool is_ecb(std::vector<uint8_t> arr);
template bool is_ecb(cryptvec arr);

