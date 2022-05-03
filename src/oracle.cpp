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


cryptvec level12_encryption_oracle(const cryptvec& pt, const cryptvec& prefix)
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

    if (!prefix.empty())
    {
        full_pt.insert(full_pt.end(), prefix.begin(), prefix.end());
    }
    full_pt.insert(full_pt.end(), pt.begin(), pt.end());
    full_pt.insert(full_pt.end(), decoded_secret.begin(), decoded_secret.end());

    return aes_encrypt_ecb(key, full_pt);
}


cryptvec break_level12_ecb_oracle(unsigned int block_size, unsigned int total_blocks, unsigned int num_pad_bytes)
{
    cryptvec known_pt {};
    cryptvec filler{};
    cryptvec pt{};

    // This variable refers to the offset of the block we which contains
    // some number secret text bytes and filler.
    unsigned int block_offset = block_size * total_blocks;

    // Generate filler that will be one byte shy of a full block size. This will also be
    // the size of the secret plaintext. It must be at least the same size in order for us
    // to "pull" the entire secret text our target block. This way we only ever have
    // to look at the last block of filler.
    filler.resize(block_offset - 1);
    // Fill the filler vector with garbage, but consistant garbage.
    std::fill(filler.begin(), filler.end(), 'A');

    // We create a plaintext buffer filled with either all 'A's (filler)
    // or filler + our plaintext.
    pt.resize(block_offset);
    std::fill(pt.begin(), pt.end(), 'A');


    for (int i = 1; i < block_offset - num_pad_bytes; i++)
    {
        // Encrypt our filler. This will produce a series of encrypted blocks, where the last block
        // of our padded text will contain some number of bytes of our secret text.
        cryptvec ct = level12_encryption_oracle(filler, {});

        // Get the block that contains all known filler + one byte (or more) of secret text.
        // This will become the ciphertext we will look for when we try to brute force all possible
        // 256 values.
        cryptvec block_to_crack = {ct.begin() + (block_offset - block_size), ct.begin() + block_offset};

        // Create a vector which will be our "guess" of our existing plaintext.
        std::copy(known_pt.begin(), known_pt.end(), pt.end() - i);
        try {
            uint8_t val = break_level12_single_byte_oracle(block_to_crack, pt, block_offset - block_size);
            known_pt.push_back(val);
        }
        catch (std::logic_error& ex)
        {
            std::cout << "There was an error finding the value at index " << i << std::endl;
            break;
        }
        // Remove some more filler, to pull another byte into our block.
        filler.pop_back();
    }

    return known_pt;
}


/**
 * We are attempting to do the following
 *
 * If our secret message is "this-is-a-secret-message" We are trying to set up
 * our encrypted blocks in the following way:
 *
 * |AAAAAAAAAAAAAAAt|his-is-a-secret-message|
 *
 * AAAAAAAAAAAAAt is our test_pt.
 * This means in the first case, we want 15 bytes of padding (one shy of the block size).
 * Then in this function we loop through the
 *
 * On the second go-around, we know one byte of the plaintext so we incorporate this into our answer. Our
 * test_pt becomes:
 *
 * AAAAAAAAAAAAAAt. As this is now 15 bytes long it has the effect of pulling one more (and only one) unknown
 * byte into the block, so it looks like this:
 *
 * |AAAAAAAAAAAAAAth|is-a-secret-message|
 *
 * Now we only need to search for the 16th byte, as we already know the 15th byte.
 * @param expected_ct
 * @param test_pt
 * @param ct_offset
 * @return
 */
uint8_t break_level12_single_byte_oracle(const cryptvec& expected_ct, cryptvec test_pt, unsigned int ct_offset)
{
    // Loop through all 256 possible byte values.
    for (unsigned int val = 0; val < 256; val++)
    {
        // Set the last byte in our test plaintext to be the guessed value.
        test_pt.back() = val;
        // Encrypt the plaintext with the guessed value.
        cryptvec ct = level12_encryption_oracle(test_pt, {});

        // Determine if our encrypted guessed plaintext is equal to the expected ciphertext.
        bool eq = std::equal(expected_ct.begin(), expected_ct.end(), ct.begin() + ct_offset);
        if (eq)
        {
            // We have discovered a value that causes our encrypted plaintext to equal our
            // expected ciphertext.
            return val;
        }
    }

    // Nothing matches. This is bad, and unrecoverable a t this level.
    throw std::logic_error("Cannot find plaintext value!");
}


/*
cryptvec level13_parse_profile(const cryptvec& encrypted_profile)
{
    if (level13_aes_key.empty())
        throw std::logic_error("Error: The AES key for level 13 has not been set. You must first generate a profile "
                               "before attempting to decrypt one.");

    cryptvec pt = aes_decrypt_ecb(level13_aes_key, encrypted_profile);
}*/