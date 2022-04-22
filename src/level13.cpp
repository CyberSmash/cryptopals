#include <iostream>
#include <string>
#include <vector>
#include <string>
#include <map>
#include "oracle.h"
#include "aes.h"
#include "helpers.hpp"
#include "cryptvec.h"

cryptvec level13_aes_key;


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

void level13_decode_cookie(const cryptvec token)
{

    if (level13_aes_key.empty())
        throw std::logic_error("Error: Cannot decrypt as the encryption key has not been set.");

    cryptvec pt = aes_decrypt_ecb<cryptvec>(level13_aes_key, token);
    if (pt.empty())
        throw std::logic_error("Could not decrypt the token for an unknown reason.");

    pt = remove_pkcs7_padding(pt);

    auto kv_map = level13_parse_kv_string(pt.to_string());
    if (kv_map["role"] == "admin")
    {
        std::cout << kv_map["email"] << " has been given admin rights." << std::endl;
    }
    else if (kv_map["role"] == "user")
    {
        std::cout << kv_map["email"] << " has the been given the role of guest." << std::endl;
    }
    else
    {
        std::cout << kv_map["email"] << " has an unknown role... " << kv_map["role"] << std::endl;
    }
    std::cout << "pt: " << pt.to_string() << std::endl;
}

std::string level13_encode_profile(std::map<std::string, std::string>& profile)
{
    std::string profile_str;
    // TODO: The [] operator has a nasty side effect that if it doesn't exist it'll be inserted into the map.
    // I'm ignoring that intentionally.
    profile_str =  "email=" + profile["email"]  + "&";
    profile_str += "uid="   + profile["uid"]    + "&";
    profile_str += "role="  + profile["role"];

    return profile_str;
}


cryptvec profile_for(std::string email)
{
    cryptvec ct;
    std::map<std::string, std::string> profile;
    if (level13_aes_key.empty())
        level13_aes_key = gen_random_key<cryptvec>(AES_BLOCK_SIZE);

    // Sanitize the input, remove any instance of & and =
    email.erase(std::remove(email.begin(), email.end(), '&'), email.end());
    email.erase(std::remove(email.begin(), email.end(), '='), email.end());

    profile.insert(std::pair<std::string, std::string>("email", email));
    profile.insert(std::pair<std::string, std::string>("uid", "10"));
    profile.insert(std::pair<std::string, std::string>("role", "user"));

    cryptvec profile_vec(level13_encode_profile(profile));
    ct = aes_encrypt_ecb(level13_aes_key, profile_vec);

    return ct;
}

std::string level13_get_profile(const std::string& email)
{
    cryptvec profile = profile_for(email);
    if (level13_aes_key.empty())
        level13_aes_key = gen_random_key<cryptvec>(AES_BLOCK_SIZE);
    cryptvec encrypted_profile = aes_encrypt_ecb(level13_aes_key, profile);

    int b64_encoded_len = Base64encode_len(encrypted_profile.size());

    // TODO: Theres probably a better way to do this in place that doesn't require a copy operation.
    char* base64_out = new char[b64_encoded_len + 1] {};
    Base64encode(base64_out, reinterpret_cast<const char*>(encrypted_profile.data()), encrypted_profile.size());
    std::string out(base64_out);
    delete[] base64_out;
    return out;
}

unsigned int find_block_size()
{
    unsigned int block_size     = 0;
    std::string email           = "A";
    cryptvec tmp_profile        = profile_for(email);
    unsigned int profile_size   = tmp_profile.size();
    unsigned int new_profile_size = profile_size;

    do
    {
        email += "A";
        tmp_profile = profile_for(email);
        new_profile_size = tmp_profile.size();
    } while(new_profile_size == profile_size);

    block_size = new_profile_size - profile_size;

    return block_size;
}

int main()
{
    std::string encoded_string("email=jordan@cybersmash.io&uid=10&role=user");
    std::map<std::string, std::string> kvp = level13_parse_kv_string(encoded_string);

    for (auto& pair : kvp)
    {
        std::cout << pair.first << "\t=\t" << pair.second << std::endl;
    }

    std::string new_profile = level13_encode_profile(kvp);


    cryptvec encrypted_profile = profile_for("jordan@cybersmash.io");
    std::cout << "Encrypted profile length: " << encrypted_profile.size() << std::endl;
    std::cout << "Encrypted profile: " << std::endl;
    std::cout << encrypted_profile << std::endl;

    level13_decode_cookie(encrypted_profile);

    // Find the block size.
    unsigned int block_size = find_block_size();
    std::cout << "Block size: " << block_size << std::endl;

    // Find the minimum number of blocks we can create.
    std::string fake_email="";
    cryptvec token = profile_for(fake_email);
    unsigned int initial_size = token.size();
    unsigned int num_blocks = initial_size / AES_BLOCK_SIZE;
    std::cout << "Smallest number of blocks: " << num_blocks << std::endl;
    int bytes_needed = 0;
    for (bytes_needed = 0; bytes_needed < AES_BLOCK_SIZE; bytes_needed++)
    {
        fake_email += "A";
        token = profile_for(fake_email);
        level13_decode_cookie(token);
        if (token.size() != initial_size)
        {
            //fake_email.size();
            std::cout << "Email length: " <<fake_email.length() << std::endl;
            std::cout << "Need: " << bytes_needed << " more bytes to fill the block." << std::endl;
            break;
        }
    }

    // Now we know how many bytes we need in the token to start a new clean block.
    // What is this? JavaScript?
    std::string admin_str("admin");
    uint8_t padding_byte = AES_BLOCK_SIZE - admin_str.size();
    std::string admin_block(AES_BLOCK_SIZE, padding_byte);
    std::copy(begin(admin_str), end(admin_str), begin(admin_block));

    std::cout << "Admin block: " << std::endl;
    print_hex(admin_block);

    // We need to add a byte here because fake_email.length() number of bytes (9 in this specific case)
    // will cause the creation of a new block. HOWEVER, because PKCS7 will add another block,
    // this does NOT mean that we have put a character of the word 'user' (the 'r') in that block.
    // What it really means is that we have hit exactly a multiple of AES_BLOCK SIZE. Therefore
    // we really need fake_email.length() + 1 bytes of padding. This means we will see the increase
    // in block size, one byte before we've actually filled up our current block.
    // Example: (! is a padding byte)
    // 8 -|email=AAAAAAAA&u|id=10&role=user!|
    // 9 -|email=AAAAAAAAA&|uid=10&role=user|!!!!!!!!!!!!!!!!
    // 10-|email=AAAAAAAAAA|&uid=10&role=use|r!!!!!!!!!!!!!!!
    // Since our padding is attempting to fill in the block we control, we cannot rely on the start of a new block to re ly
    // on that, but instead the start of a new block + 1, which indicates we have successfully filled our current block.

    std::string padding(fake_email.length() + 1, 'A');
    // Get our evil block.
    std::cout << "Padding plus block: " << padding+admin_block << std::endl;
    cryptvec evil_token = profile_for(padding + admin_block);
    std::cout << "Evil token: " << std::endl;
    std::cout << evil_token << std::endl;

    // Get the "admin" slice of our token:
    cryptvec admin_slice(16);
    std::copy(begin(evil_token) + AES_BLOCK_SIZE,
                       begin(evil_token) + 2 * AES_BLOCK_SIZE, begin(admin_slice));
    std::cout << "admin slice: " << std::endl;
    std::cout << admin_slice << std::endl;

    // Get our victim chunk. We need to "push" the word "user" into the last block.
    // The amount of padding is calculated by the following:
    // from the above explanation we already know we need fake_email.length() + 1 to get the letter
    // 'r' of "user" into the final block. This leaves 3 letters left to push, so we add 3.
    std::string evil_input(fake_email.length() + 4, 'a');
    cryptvec victim = profile_for(evil_input);
    std::cout << "Victim token: " << std::endl;
    std::cout << victim << std::endl;

    std::copy(begin(admin_slice), end(admin_slice),
              end(victim) - AES_BLOCK_SIZE);

    std::cout << "Finalized victim " << std::endl;
    std::cout << victim << std::endl;

    level13_decode_cookie(victim);

    return 0;
}