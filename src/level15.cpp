/**
 * Create a pkcs7 validation routine.
 */
#include <iostream>
#include "oracle.h"
#include "aes.h"
#include "helpers.hpp"
#include "cryptvec.h"

void test_padding()
{

}

int main()
{
    cryptvec a("ICE ICE BABY\x04\x04\x04\x04");
    cryptvec tmp;
    try
    {
        tmp = remove_pkcs7_padding(a);
    }
    catch(const std::logic_error &ex)
    {
        std::cout << "Failure.That padding was supposed to have been correct." << std::endl;
        return 1;
    }

    std::cout << "Removed padding: " << tmp << std::endl;
    cryptvec b("ICE ICE BABY\x05\x05\x05\x05\x05");

    try
    {
        tmp = remove_pkcs7_padding(b);
    }
    catch(const std::logic_error &ex)
    {
        std::cout << "Testing B" << std::endl;
        std::cout << "Exception caught. That's OK this one was supposed to be bad." << std::endl;
    }

    cryptvec c("ICE ICE BABY\x01\x02\x03\x04");

    try
    {
        std::cout << "Testing C " << std::endl;
        tmp = remove_pkcs7_padding(c);
    }
    catch(const std::logic_error &ex)
    {
        std::cout << "Exception caught. That's OK this one was supposed to be bad." << std::endl;
    }

}