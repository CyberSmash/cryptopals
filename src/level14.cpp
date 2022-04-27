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

int main()
{
    cryptvec my_pt = {};

    cryptvec ct = level14_encryption_oracle(my_pt);

    unsigned int smallest_size = ct.size();
    std::cout << "[+] Current smallest size: " << smallest_size << std::endl;

    // Find the block size
    int block_size = 0;
    for (int i = 0; i < 512; i++)
    {
        ct = level14_encryption_oracle(my_pt);
        if (ct.size() > smallest_size)
        {
            block_size = ct.size() - smallest_size;
            break;
        }
        my_pt.push_back(0x41);
    }

    std::cout << "[+] Block size: " << block_size << std::endl;
    std::cout << "[+] Number of blocks in smallest PT: " << smallest_size / block_size << std::endl;

    // Determine if we are in ECB mode:
    my_pt.resize(block_size * 3);
    std::fill(my_pt.begin(), my_pt.end(), 0x41);
    ct = level14_encryption_oracle(my_pt);
    bool ecb = is_ecb(ct);
    if (ecb)
    {
        std::cout << "[+] The encryption is ECB Mode." << std::endl;
    }
    else
    {
        std::cout << "[-] The encryption is not ECB Mode. That's a problem, it should be, we cannot continue."<< std::endl;
        return 1;
    }
    // Determine the size of the plaintext and the random bytes at the beginning.
    my_pt.resize(1);
    for (int i = 0; i < 512; i++)
    {

        ct = level14_encryption_oracle(my_pt);
        if (is_ecb(ct))
        {
            std::cout << "[+] Original size without any data added: " << smallest_size << std::endl;
            std::cout << "[+] Bytes with a repeat block: " << ct.size() << std::endl;
            std::cout << "[+] Number of bytes to get a repeat block: " << my_pt.size() << std::endl;
            std::cout << "[+] Thes size of my pt vec:" << my_pt.size() << std::endl;
            std::cout << "[+] Difference in size: " << smallest_size - my_pt.size() << std::endl;
            std::cout << "[+] Blocks and bytes: " << my_pt.size() / block_size << ", " << my_pt.size() % block_size << std::endl;
            break;
        }
        my_pt.push_back(0x41);
    }

    int match_count = 0;
    int repeat_block_index_begin = 0;
    for (int i = 0; i < ct.size() - 16; i++)
    {
        if (ct[i] == ct[i + 16])
        {
            match_count += 1;
        }
        else
        {
            match_count = 0;
        }
        if (match_count == 16)
        {
            std::cout << "[+] Repeat data starts at index: " << i - block_size << " block: " << (i + block_size) / block_size  << std::endl;
            // TODO: Why is this + 1?
            repeat_block_index_begin = i - block_size + 1;
            break;
        }
    }
    std::cout << ct << std::endl << std::endl;
    cryptvec repeat_block = {ct.begin() + repeat_block_index_begin, ct.begin() + repeat_block_index_begin + block_size};
    std::cout << repeat_block << std::endl;
    std::cout << "Random prefix size: " << repeat_block_index_begin - (my_pt.size() % block_size) << std::endl;

    // TODO: We now know the separation point between the prefix the controlled data, and the hidden data.
    // TODO: This means we now know how big our test plaintext needs to be to crack this bad boi.

    return 0;
}