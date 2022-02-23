#include <iostream>

#include <vector>
using std::vector;

#include <cstdio>

#include <cstdint>
#include <string>
#include <algorithm>

#include "helpers.hpp"
#include "base64.h"


uint8_t hex_char_to_byte(char c)
{
    uint8_t out = 0;
    if (c >= 'A' && c <= 'F')
    {
        return c - 'A' + 10;
    }
    else if (c >= 'a' && c <='f')
    {
        return c - 'a' + 10;
    }
    else if (c >= '0' && c <= '9')
    {
        return c - '0';
    }
    throw std::invalid_argument("The argument provided is not a valid hex character.");
}


vector<uint8_t> hex_str_to_bytes(const std::string& hex_string)
{
    unsigned int buffer_length = 0;
    vector<uint8_t> out_buffer;
    int buffer_index = 0;

    if (hex_string.length() % 2 != 0)
    {
        throw std::invalid_argument("The provided hex string is not an even number of characters.");
    }

    buffer_length = hex_string.length() / 2;
    out_buffer.resize(buffer_length);

    const char* current = hex_string.c_str();

    while (*current && *(current+1))
    {
        out_buffer[buffer_index] = hex_char_to_byte(*current) << 4 | hex_char_to_byte(current[1]);
        current += 2;
        buffer_index++;
    }

    return out_buffer;
}


void print_hex(vector<uint8_t> buffer)
{
    for (int i = 0; i < buffer.size(); i++)
    {
        if (i > 0 && i % 16 == 0)
        {
            puts("\n");
        }

        printf("%02X ", buffer[i]);
    }
    puts("\n");
}


char* hex_bytes_to_base64(vector<uint8_t> buffer)
{
    const uint8_t* byte_buff = buffer.data();
    int b64_buffer_length = Base64encode_len(buffer.size());

    // The braces here is a little-known feature that will initialize the buffer to 0's.
    // NOTE: As the base64 library provides no documentation, it's not clear if the
    // length provided provides room for a null byte. I've added one for good measure.
    char* b64_out = new char[b64_buffer_length + 1] {};
    Base64encode(b64_out, reinterpret_cast<const char *>(byte_buff), buffer.size());
    return b64_out;
}

std::string vector_to_string(vector<uint8_t> vec)
{
    std::string result;
    result.resize(vec.size());

    std::transform(vec.begin(), vec.end(), result.begin(), [](uint8_t val) -> char {return static_cast<char>(val);});
    return result;
}