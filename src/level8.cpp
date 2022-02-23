#include <iostream>
using std::cout;
using std::endl;

#include "aes.h"
#include "cryptvec.h"
#include "helpers.hpp"
#include "file_ops.h"
#include <vector>
int main()
{

    vector<std::string> file_lines = read_file_lines("../data/level8_data.txt");
    for (const std::string& line : file_lines)
    {
        vector<uint8_t> bytes = hex_str_to_bytes(line);
        bool found = is_ecb(bytes);
        if (found)
            std::cout << "ECB Found: " << line;
    }

    return 0;
}