/**
 * Find the hidden plaintext like in level 12 except this time
 * there is a random amount of data appended to the front of the
 * controlled message:
 * AES_128_ECB(RANDOM DATA || CONTROLLED DATA || SECRET MESSAGE)
 */

#include <iostream>
#include "oracle.h"
#include "aes.h"
#include "helpers.hpp"
#include "cryptvec.h"
#include <random>
#include <ctime>

cryptvec level14_encryption_oracle(const cryptvec& plaintext)
{
    static cryptvec prefix;
    if (prefix.empty())
    {
        srand(time(NULL));
        int random_prefix_bytes = rand() % 256;
        std::cout << "[?] Random bytes count: " << random_prefix_bytes << std::endl;
        prefix = gen_random_key<cryptvec>(random_prefix_bytes);
    }
    return level12_encryption_oracle(plaintext, prefix);

}

uint8_t break_level14_single_byte_oracle(const cryptvec& expected_ct, cryptvec test_pt, unsigned int ct_offset, unsigned int chop_blocks)
{
    // Loop through all 256 possible byte values.
    std::cout << "Chop blocks: " << chop_blocks << std::endl;
    std::cout << "CT offset (block): " << ct_offset / 16 << std::endl;
    std::cout << "test Plaintext: "  << std::endl << test_pt << std::endl;
    for (unsigned int val = 0; val < 256; val++)
    {
        // Set the last byte in our test plaintext to be the guessed value.
        test_pt.back() = val;
        // Encrypt the plaintext with the guessed value.
        cryptvec ct = level14_encryption_oracle(test_pt);
        ct = {ct.begin() + (chop_blocks * 16), ct.end()};
        // Determine if our encrypted guessed plaintext is equal to the expected ciphertext.
        if (val == 0)
        {
            std::cout << "expected ct: " << std::endl << expected_ct << std::endl << std::endl;
        }
        bool eq = std::equal(expected_ct.begin(), expected_ct.end(), ct.begin() + ct_offset);
        if (val == 0)
        {
            cryptvec tmp = {ct.begin() + ct_offset, ct.begin() + ct_offset + 16};
            std::cout << tmp << std::endl << std::endl;
        }

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

cryptvec break_level14_ecb_oracle(unsigned int block_size, unsigned int num_secret_blocks,
                                  unsigned int num_end_pad_bytes, unsigned int num_random_blocks,
                                  unsigned int num_random_pad_bytes)
{
    cryptvec known_pt;
    cryptvec filler;
    cryptvec pt;

    // This variable refers to the offset of the block we which contains
    // some number secret text bytes and filler.
    unsigned int num_filler_bytes = (block_size * num_secret_blocks) + num_random_pad_bytes;
    unsigned int ct_block_offset = (block_size * num_secret_blocks);
    unsigned int filler_blocks = num_filler_bytes / block_size;
    // Generate filler that will be one byte shy of a full block size. This will also be
    // the size of the secret plaintext. It must be at least the same size in order for us
    // to "pull" the entire secret text our target block. This way we only ever have
    // to look at the last block of filler.
    filler.resize(num_filler_bytes - 1);
    // Fill the filler vector with garbage, but consistant garbage.
    std::fill(filler.begin(), filler.end(), 'A');

    // We create a plaintext buffer filled with either all 'A's (filler)
    // or filler + our plaintext.
    pt.resize(num_filler_bytes);
    std::fill(pt.begin(), pt.end(), 'A');

    for (int i = 1; i < num_filler_bytes - num_end_pad_bytes; i++)
    {
        // Encrypt our filler. This will produce a series of encrypted blocks, where the last block
        // of our padded text will contain some number of bytes of our secret text.
        cryptvec ct = level14_encryption_oracle(filler);

        // Chop off all the beginning random data blocks.
        std::cout << ct << std::endl << std::endl;
        ct = {ct.begin() + (block_size * num_random_blocks), ct.end()};
        std::cout << ct << std::endl;
        // Get the block that contains all known filler + one byte (or more) of secret text.
        // This will become the ciphertext we will look for when we try to brute force all possible
        // 256 values.
        cryptvec block_to_crack = {ct.begin() + (ct_block_offset - block_size), ct.begin() + ct_block_offset};
        std::cout << "Block to crack: " << block_to_crack << std::endl << std::endl;
        // Create a vector which will be our "guess" of our existing plaintext.
        std::copy(known_pt.begin(), known_pt.end(), pt.end() - i);
        std::cout << "Test PT: " << std::endl << pt << std::endl << std::endl;
        try {

            uint8_t val = break_level14_single_byte_oracle(block_to_crack,
                                                           pt,
                                                           ct_block_offset - block_size,
                                                           num_random_blocks);
            known_pt.push_back(val);
            std::cout << "Known pt: " << std::endl << known_pt << std::endl;
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


int main() {
    cryptvec my_pt = {};

    cryptvec ct = level14_encryption_oracle(my_pt);

    unsigned int smallest_size = ct.size();
    std::cout << "[+] Current smallest size: " << smallest_size << std::endl;
    std::cout << "[+] Smallest CT: " << std::endl;
    std::cout << ct << std::endl << std::endl;
    // Find the block size
    int block_size = 0;
    int padding_bytes = 0;
    for (int i = 0; i < 512; i++, padding_bytes++) {
        ct = level14_encryption_oracle(my_pt);
        if (ct.size() > smallest_size) {
            block_size = ct.size() - smallest_size;
            break;
        }
        my_pt.push_back(0x41);
    }
    std::cout << "[+] Padding bytes: " << padding_bytes << std::endl;
    std::cout << "[+] Block size: " << block_size << std::endl;
    std::cout << "[+] Number of blocks in smallest CT: " << smallest_size / block_size << std::endl;

    // Determine if we are in ECB mode:
    my_pt.resize(block_size * 3);
    std::fill(my_pt.begin(), my_pt.end(), 0x41);
    ct = level14_encryption_oracle(my_pt);
    bool ecb = is_ecb(ct);
    if (ecb) {
        std::cout << "[+] The encryption is ECB Mode." << std::endl;
    } else {
        std::cout << "[-] The encryption is not ECB Mode. That's a problem, it should be, we cannot continue."
                  << std::endl;
        return 1;
    }
    // Determine the size of the plaintext and the random bytes at the beginning.
    my_pt.resize(1);
    for (int i = 0; i < 512; i++) {

        ct = level14_encryption_oracle(my_pt);
        if (is_ecb(ct)) {
            std::cout << "[+] Original size without any data added: " << smallest_size << std::endl;
            std::cout << "[+] Bytes with a repeat block: " << ct.size() << std::endl;
            std::cout << "[+] Number of bytes to get a repeat block: " << my_pt.size() << std::endl;
            std::cout << "[+] Thes size of my pt vec:" << my_pt.size() << std::endl;
            std::cout << "[+] Difference in size: " << smallest_size - my_pt.size() << std::endl;
            std::cout << "[+] Blocks and bytes: " << my_pt.size() / block_size << ", " << my_pt.size() % block_size
                      << std::endl;
            break;
        }
        my_pt.push_back(0x41);
    }

    int match_count = 0;
    int repeat_block_index_begin = 0;
    for (int i = 0; i < ct.size() - 16; i++) {
        if (ct[i] == ct[i + 16]) {
            match_count += 1;
        } else {
            match_count = 0;
        }
        if (match_count == 16) {
            std::cout << "[+] Repeat data starts at index: " << i - block_size << " block: "
                      << (i + block_size) / block_size << std::endl;
            // TODO: Why is this + 1?
            repeat_block_index_begin = i - block_size + 1;
            break;
        }
    }
    std::cout << ct << std::endl << std::endl;
    cryptvec repeat_block = {ct.begin() + repeat_block_index_begin, ct.begin() + repeat_block_index_begin + block_size};
    std::cout << repeat_block << std::endl;
    std::cout << "Random prefix size: " << repeat_block_index_begin - (my_pt.size() % block_size) << std::endl;
    unsigned int random_prefix_size = repeat_block_index_begin - (my_pt.size() % block_size);
    // TODO: We now know the separation point between the prefix the controlled data, and the hidden data.
    // TODO: This means we now know how big our test plaintext needs to be to crack this bad boi.
    unsigned int num_random_pad_bytes = block_size - (random_prefix_size % 16);
    std::cout << "Need " << num_random_pad_bytes << " Bytes to fill the last block of random data, before a fully controlled block." << std::endl;
    unsigned int num_prefix_blocks = (random_prefix_size + num_random_pad_bytes) / 16;

    std::cout << "Number of blocks of random data after any padding applied " << num_prefix_blocks << std::endl;
    std::cout << "Number of total blocks in smallest CT: " << smallest_size / 16 << std::endl;
    //unsigned int num_secret_blocks = ( / block_size ) - num_prefix_blocks;

    std::cout << "Smallest CT size: " << smallest_size << std::endl;
    std::cout << "Number of secret blocks: " << ((smallest_size + num_random_pad_bytes) / 16) - num_prefix_blocks << std::endl;
    cryptvec known_pt = break_level14_ecb_oracle(block_size,
                                                 ((smallest_size + num_random_pad_bytes) / 16) - num_prefix_blocks,
                             padding_bytes,
                             num_prefix_blocks,
                             num_random_pad_bytes
                             );
    std::cout << known_pt.to_string() << std::endl;
    return 0;
}