#include <iostream>
#include <algorithm>

#include "aes.h"
#include "helpers.hpp"
#include "cryptvec.h"
#include "oracle.h"

int main()
{

    // Start with one block size.
    cryptvec pt {};
    pt.resize(16);

    double num_samples = 100;
    double average = 0.0;

    while (average < 0.48 || average > 0.52)
    {
        std::fill(pt.begin(), pt.end(), 0x41);

        // Try to guess ECB or CBC for this many samples.
        for (int i = 0; i < num_samples; i++)
        {
            bool answer;
            cryptvec ct = level11_encryption_oracle(pt, answer);
            bool res = is_ecb(ct);
            if (res)
                average += 1;

        }
        average /= num_samples;
        if (average < 0.48 || average > 0.52)
        {
            // We aren't within our range for being able to guess ECB / CBC. Add a block.
            pt.insert(pt.end(), pt.begin(), pt.begin() + AES_BLOCK_SIZE);
        }
        else
        {
            break;
        }
    }


    std::cout << "We think we can detect ECB / CBC. Lets test it. Rate: " << average << std::endl;

    for (int i = 0; i < 100; i++)
    {
        bool answer;
        cryptvec ct = level11_encryption_oracle(pt, answer);
        bool ecb = is_ecb(ct);
        if (ecb != answer)
        {
            std::cout << "Failure! We did not successfully identify ECB. " << std::endl;
            return 1;
        }
    }
    std::cout << "Success! We can identify ECB! Blocks need " << pt.size() / AES_BLOCK_SIZE << std::endl;

    return 0;
}