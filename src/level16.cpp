/**
 * Create a AES-CBC bit-flipping attack.
 */
#include <iostream>
#include <sstream>
#include "oracle.h"
#include "aes.h"
#include "helpers.hpp"
#include "cryptvec.h"

cryptvec MASTER_KEY;
cryptvec IV;

struct block_cipher_info {
    size_t block_size = 0;
    size_t bytes_until_new_block = 0;
    size_t total_meta_data_size = 0;
    size_t start_metadata_size = 0;
};

/*
 * A A A A | B B B B
 * A A A A | C C C C | B B B B
 *
 * A A A A | A B B B | B P P P
 * A A A A | A C B B | B B P P
 * A A A A | A C C B | B B B P
 * A A A A | A C C C | B B B B
 * A A A A | A C C C | C B B B | B P P P
 * In this case where B is a perfect block size, we can just determine that when we get a new block,
 * we know that we needed n - 1 bytes.
 *
 * A A A A | A B B B | B B P P
 * A A A A | A C B B | B B B P
 * A A A A | A C C B | B B B B
 * A A A A | A C C C | B B B B | B P P P
 * A A A A | A C C C | C B B B | B B P P
 *
 * Really we determine what block isn't stable, then add n values until it stabilizes.
 * Then we take n-1, and that gives us the number of bytes we need to stabilize the block, giving
 * us the length of the starting meta data.
 */

cryptvec level16_oracle(const cryptvec& iv, const cryptvec& key, std::string user_data)
{
    std::stringstream ss;

    const std::string prefix("comment1=cooking%20MCs;userdata=");
    const std::string suffix(";comment2=%20like%20a%20pound%20of%20bacon");

    user_data = find_and_replace_all("=", user_data, "\"=\"");
    user_data = find_and_replace_all(";", user_data, "\";\"");

    ss << prefix << user_data << suffix;

    cryptvec pt = cryptvec(ss.str());

    return aes_encrypt_cbc(iv, key, pt);
}

/**
 * A stupid simple authentication check.
 * @param iv - The initialization vector
 * @param key - The key
 * @param ct - The cipher text
 * @param print - Will print the plain text when true.
 * @return True if we successfully found the staring "admin=true" in the PT. False otherwise.
 */
bool level16_is_authenticated(const cryptvec& iv, const cryptvec& key, const cryptvec& ct, bool print = false) {

    cryptvec pt = aes_decrypt_cbc(iv, key, ct);
    std::string pt_string = pt.to_string();
    size_t found = pt_string.find("admin=true");
    if (print) {
        std::cout << "[+] " << pt_string << std::endl;
    }
    return found != std::string::npos;
}

/**
 * Gets the start of the data that the user can provide to the oracle.
 *
 * Is this overly complicated?
 *
 * @param iv - The IV used in increption.
 * @param key - The key used in encryption
 * @param info - A structure that will receive the information related to the cryptosystem.
 */
void find_user_data_start(const cryptvec& iv, const cryptvec& key, block_cipher_info& info) {
    cryptvec empty_ct = level16_oracle(iv, key, "");
    cryptvec full_ct = level16_oracle(iv, key, "A");
    size_t num_blocks = empty_ct.size() / info.block_size;

    int num_matching_blocks = 0;
    // Determine how many blocks are the same
    for (int i = 0; i < num_blocks; i++) {
        bool same = std::equal(empty_ct.begin() + (16*i), empty_ct.begin() + (16*i) + 16, full_ct.begin() + (16*i));
        if (same) {
            num_matching_blocks++;
        }
    }

    // Now we know how many blocks are the same. This gives us the block that changes.
    // Now add bytes until the current block stabilizes.
    cryptvec current_ct = empty_ct;

    int block_start = num_matching_blocks * 16;
    int block_end = num_matching_blocks * 16 + 16;

    for (int i = 0; i < info.block_size + 1; i++) {
        std::string test_data(i+1, 'A');
        cryptvec test_ct = level16_oracle(iv, key, test_data);
        bool stable = std::equal(current_ct.begin() + block_start,
                                 current_ct.begin() + block_end,
                                 test_ct.begin() + block_start);
        if (stable) {
            info.start_metadata_size = (num_matching_blocks + 1) * 16 - (test_data.length() - 1);
            break;
        }

        current_ct = test_ct;
    }
}

block_cipher_info get_cipher_info(const cryptvec& iv, const cryptvec& key) {
    cryptvec empty_ct = level16_oracle(iv, key, "");
    size_t start_size = empty_ct.size();
    block_cipher_info info = {};

    std::string user_data = "A";
    for (int i = 0; i < 512; i++) {
        cryptvec new_ct = level16_oracle(iv, key, user_data);
        user_data += "A";
        if (new_ct.size() != start_size) {
            info.block_size = new_ct.size() - start_size;
            info.bytes_until_new_block = user_data.length() - 1;
            info.total_meta_data_size = empty_ct.size() - info.bytes_until_new_block;
            break;
        }

    }
    find_user_data_start(iv, key, info);
    return info;
}

int main()
{
    IV = gen_random_key<cryptvec>(AES_BLOCK_SIZE);
    MASTER_KEY = gen_random_key<cryptvec>(AES_BLOCK_SIZE);
    block_cipher_info info = get_cipher_info(IV, MASTER_KEY);

    std::cout << "[+] Block Size: " << info.block_size << std::endl;
    std::cout << "[+] Bytes Until Next Block " << info.bytes_until_new_block << std::endl;
    std::cout << "[+] Total Metadata Size " << info.total_meta_data_size << std::endl;

    // Create a ct with two full blocks we can mess with
    size_t num_chars = (info.block_size - (info.start_metadata_size % info.block_size)) + (info.block_size * 2);

    std::cout << "[+] The number of characters needed to get two complete blocks: " << num_chars << std::endl;
    cryptvec test_bed = level16_oracle(IV, MASTER_KEY, std::string(num_chars, 'A'));
    size_t controlled_block_start = 0;

    // This if statement might not be needed if I could figure out some
    // super cool formula for doing this mathematically, but oh well.
    if (info.start_metadata_size % 16 == 0) {
        controlled_block_start = info.start_metadata_size;
    }
    else {
        controlled_block_start = ((info.start_metadata_size + info.block_size) / info.block_size) * info.block_size;
    }

    test_bed[controlled_block_start] = test_bed[controlled_block_start] ^ 0x20;
    test_bed[controlled_block_start + 1] = test_bed[controlled_block_start + 1] ^ ('d' ^ 'A');
    test_bed[controlled_block_start + 2] = test_bed[controlled_block_start + 2] ^ ('m' ^ 'A');
    test_bed[controlled_block_start + 3] = test_bed[controlled_block_start + 3] ^ ('i' ^ 'A');
    test_bed[controlled_block_start + 4] = test_bed[controlled_block_start + 4] ^ ('n' ^ 'A');
    test_bed[controlled_block_start + 5] = test_bed[controlled_block_start + 5] ^ ('=' ^ 'A');
    test_bed[controlled_block_start + 6] = test_bed[controlled_block_start + 6] ^ ('t' ^ 'A');
    test_bed[controlled_block_start + 7] = test_bed[controlled_block_start + 7] ^ ('r' ^ 'A');
    test_bed[controlled_block_start + 8] = test_bed[controlled_block_start + 8] ^ ('u' ^ 'A');
    test_bed[controlled_block_start + 9] = test_bed[controlled_block_start + 9] ^ ('e' ^ 'A');
    test_bed[controlled_block_start + 10] = test_bed[controlled_block_start + 10] ^ (';' ^ 'A');

    bool win = level16_is_authenticated(IV, MASTER_KEY, test_bed, true);
    if (win) {
        std::cout << "[+] Authentication SUCCESSFUL." << std::endl;
    }
    else {
        std::cout << "[-] Authentication FAILED." << std::endl;
    }

    return 0;
}