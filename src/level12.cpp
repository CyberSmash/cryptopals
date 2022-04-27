/**
 * Discover the secret data appended to plaintext, using an AES-128 ECB oracle.
 */

#include <iostream>
#include "oracle.h"
#include "aes.h"
#include "helpers.hpp"
#include "cryptvec.h"


int main()
{
    cryptvec pt {};
    cryptvec ct = level12_encryption_oracle(pt, {});

    std::cout << "Encrypted data: " << std::endl;
    std::cout << ct << std::endl;

    unsigned int original_ct_size = ct.size();
   // We pretend we don't know the block size. Identify it. We'll stop at a block size of 512 bytes. That would
   // just be too many bytes. Probably? We need to find two block expansions, as we don't know how much padding is
   // in the first block.
   unsigned int block_size = 0;
   unsigned int padding_bytes = 0;
   for (int i = 0; i < 512; i++)
   {
       pt.push_back(0x41);
       ct = level12_encryption_oracle(pt, {});
       if (ct.size() > original_ct_size)
       {
           block_size = ct.size() - original_ct_size;
           break;
       }
       else
       {
           padding_bytes += 1;
       }
   }
   unsigned int num_blocks = original_ct_size / block_size;

    std::cout << "[+] Block size detected: " << block_size << std::endl;
    std::cout << "[+] Padding bytes detected: " << padding_bytes << std::endl;
    std::cout << "[+] Size of secret plaintext: " << original_ct_size - padding_bytes << std::endl;
    std::cout << "[+] Number of blocks: " << num_blocks << std::endl;

    pt.resize(block_size * 2);
    std::fill(pt.begin(), pt.end(), 'A');

    // Detect that we are using ECB.
    ct = level12_encryption_oracle(pt, {});
    bool ecb = is_ecb(ct);
    if (!ecb)
    {
        std::cout << "Error: This doesn't appear to be an ECB cipher. That's wrong. It should." << std::endl;
        return 1;
    }
    std::cout << "[+] Cipher appears to be in ECB mode." << std::endl;

    cryptvec known_pt = break_level12_ecb_oracle(block_size, num_blocks, padding_bytes);
    std::string recovered_block = {known_pt.begin(), known_pt.end()};

    std::cout << "PT: " << recovered_block << std::endl;
    return 0;
}