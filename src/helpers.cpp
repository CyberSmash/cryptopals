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

template <typename T>
void print_hex(T buffer)
{
    int count = 0;
    for (auto it = begin(buffer); it != end(buffer); it++, count++)
    {
        if (count > 0 && count % 16 == 0)
        {
            puts("\n");
        }

        printf("%02X ", *it);
    }
    puts("\n");
}
template void print_hex(vector<uint8_t> buffer);
template void print_hex(std::string str);

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


std::vector<std::string> split_by_delimiter(const std::string& input, char delim)
{
    std::vector<std::string>    result  = {};
    std::string                 tmp     = {};
    unsigned long               last    = 0;
    unsigned long               pos     = 0;

    while (pos != std::string::npos)
    {
        pos     = input.find(delim, last);
        tmp     = input.substr(last, pos - last);
        last    = pos + 1;
        // There's probably a better way to check for this
        // before constructing a new string ... but this works.
        if (tmp.empty())
            continue;

        result.push_back(tmp);
    }

    return result;
}


std::pair<std::string, std::string> get_key_value(const std::string& kv_string)
{
    std::pair<std::string, std::string> result = {};
    vector<std::string> key_value = split_by_delimiter(kv_string, '=');
    if (key_value.size() != 2)
        throw std::logic_error("I was expecting to only have exactly two results in k=v string. This is not the case.");

    result.first = key_value[0];
    result.second = key_value[1];

    return result;
}
