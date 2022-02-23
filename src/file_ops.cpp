
#include "file_ops.h"
#include <iostream>
#include <fstream>
#include <streambuf>
#include "base64.h"

using std::ifstream;

vector<string> read_file_lines(string filename)
{
    vector<string> lines;
    std::string line;
    ifstream file(filename);

    if (!file.is_open())
        throw std::invalid_argument("Error: The filename provided is incorrect.");

    while (std::getline(file, line))
    {
        lines.push_back(line);
    }
    return lines;
}

std::string read_entire_file(string filename)
{
    ifstream file(filename);

    if (!file.is_open())
        throw std::invalid_argument("Error: The filename provided is incorrect.");

    std::string file_data((std::istreambuf_iterator<char>(file)),
                          std::istreambuf_iterator<char>());

    return file_data;

}

std::vector<uint8_t> read_base64_decode(const std::string& filename)
{
    std::string file;
    int base64_decide_size = 0;
    std::vector<uint8_t> ret;

    try {
        file = read_entire_file(filename);
    }
    catch (std::invalid_argument& ex)
    {
        std::cout << "Error: Cannot read file. Will not be able to base64 decode in read_base64_decode()." << std::endl;
        throw;
    }

    // Our base64 decoder, doesn't care much for newlines. So lets remove them.
    file.erase(std::remove(file.begin(), file.end(), '\r'), file.end());
    file.erase(std::remove(file.begin(), file.end(), '\n'), file.end());

    // Get teh size of the base64 structure.
    base64_decide_size = Base64decode_len(file.data());
    ret.resize(base64_decide_size);

    Base64decode(reinterpret_cast<char*>(ret.data()), file.data());

    return ret;
}
