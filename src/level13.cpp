#include <iostream>
#include <string>
#include <vector>
#include <string>
#include <map>
#include "oracle.h"
#include "aes.h"
#include "helpers.hpp"
#include "cryptvec.h"


int main()
{
    //std::vector<std::string> splits = split_by_delimiter(std::string("foo=bar&baz=qux&zap=zazzle"), '&');
    /*
    for (auto& split: splits)
    {
        std::cout << split << std::endl;
        auto kv = get_key_value(split);
        std::cout << "Key:" << kv.first << " Value: " << kv.second << std::endl;
    }*/
    std::string encoded_string("foo=bar&baz=qux&zap=zazzle");
    std::map<std::string, std::string> kvp = level13_parse_kv_string(encoded_string);

    for (auto& pair : kvp)
    {
        std::cout << pair.first << "\t=\t" << pair.second << std::endl;
    }
    return 0;
}