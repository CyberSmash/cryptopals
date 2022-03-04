#include <random>
#include <map>
#include "oracle.h"
#include "cryptvec.h"
#include "aes.h"
#include "helpers.hpp"

cryptvec level11_encryption_oracle(const cryptvec& pt, bool& is_ecb)
{
    cryptvec key = gen_random_key<cryptvec>(AES_BLOCK_SIZE);
    cryptvec ct {};
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(5, 10);


    int num_padding_bytes = dist(rd);
    int ecb_or_cbc = dist(rd) % 2;

    // Get a random key
    cryptvec begin_bytes = gen_random_key<cryptvec>(num_padding_bytes);

    // Add in the padding bytes at the beginning
    cryptvec final_pt = {begin_bytes.begin(), begin_bytes.end()};

    // Add in the plaintext
    final_pt.insert(final_pt.end(), pt.begin(), pt.end());

    // Add in padding bytes at the end.
    final_pt.insert(final_pt.end(), begin_bytes.begin(), begin_bytes.end());

    if (ecb_or_cbc == 0)
    {
        is_ecb = true;
        ct = aes_encrypt_ecb(key, final_pt, true);
    }
    else
    {
        is_ecb = false;
        cryptvec iv = gen_random_key<cryptvec>(AES_BLOCK_SIZE);
        ct = aes_encrypt_cbc(iv, key, final_pt);
    }

    return ct;
}


cryptvec level12_encryption_oracle(const cryptvec& pt)
{
    // Generate a key if one doesn't exist yet.
    static cryptvec key {};
    if (key.empty())
    {
        key = gen_random_key<cryptvec>(AES_BLOCK_SIZE);
    }
    // We don't base64 decode this and pretend we don't know what it says.
    const char* static_plaintext = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
                                   "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
                                   "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
                                   "YnkK";
    int decode_len = Base64decode_len(static_plaintext);
    cryptvec decoded_secret(decode_len);
    cryptvec full_pt {};
    Base64decode(reinterpret_cast<char *>(decoded_secret.data()), static_plaintext);

    full_pt.insert(full_pt.end(), pt.begin(), pt.end());
    full_pt.insert(full_pt.end(), decoded_secret.begin(), decoded_secret.end());

    return aes_encrypt_ecb(key, full_pt);
}


cryptvec break_level12_ecb_oracle(unsigned int block_size, unsigned int total_blocks, unsigned int num_pad_bytes)
{
    cryptvec known_pt {};
    cryptvec filler{};
    cryptvec pt{};

    unsigned int block_offset = block_size * (total_blocks);
    filler.resize(block_offset - 1);
    std::fill(filler.begin(), filler.end(), 'A');

    pt.resize(block_offset);
    std::fill(pt.begin(), pt.end(), 'A');

    for (int i = 1; i < block_offset - num_pad_bytes; i++)
    {
        cryptvec ct = level12_encryption_oracle(filler);
        cryptvec first_block = {ct.begin() + (block_offset - block_size), ct.begin() + block_offset};

        // Copy in the bytes we already know.
        std::copy(known_pt.begin(), known_pt.end(), pt.end() - i);
        try {
            uint8_t val = break_level12_single_byte_oracle(first_block, pt, block_offset - block_size);
            known_pt.push_back(val);
        }
        catch (std::logic_error& ex)
        {
            std::cout << "There was an error finding the value at index " << i << std::endl;
            break;
        }

        filler.pop_back();
    }

    return known_pt;
}


uint8_t break_level12_single_byte_oracle(const cryptvec& expected_ct, cryptvec test_pt, unsigned int ct_offset)
{

    for (unsigned int val = 0; val < 256; val++)
    {
        test_pt.back() = val;
        cryptvec ct = level12_encryption_oracle(test_pt);
        bool eq = std::equal(expected_ct.begin(), expected_ct.end(), ct.begin() + ct_offset);
        if (eq)
        {
            return val;
        }
    }

    throw std::logic_error("Cannot find plaintext value!");
}


std::map<std::string, std::string> level13_parse_kv_string(const std::string& kv_string)
{
    std::map<std::string, std::string> result = {};
    std::vector<std::string> key_value_pairs = split_by_delimiter(kv_string, '&');
    if (key_value_pairs.empty())
    {
        // Return an empty map of key value pairs.
        return result;
    }

    for (auto& kv_pair : key_value_pairs)
    {
        std::pair<std::string, std::string> kvp = get_key_value(kv_pair);
        if (kvp.first.empty() || kvp.second.empty())
            continue;
        result.insert(kvp);
    }
    return result;
}


