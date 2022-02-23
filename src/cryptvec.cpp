//
// Created by Jordan Sebastian on 2/15/22.
//

#include "cryptvec.h"

#include <vector>
using std::vector;
#include <algorithm>
#include <string>
#include "hamming.h"

template <typename T>
cryptvec::cryptvec(const T& data)
{
    resize(data.size());
    std::copy(data.begin(), data.end(), begin());
}

cryptvec::cryptvec(const char* data)
{
    if (data == nullptr)
        throw std::invalid_argument("The data passed to the cryptvec constructor cannot be a null pointer.");
    size_t len = strlen(data);

    if (len == 0)
        throw std::invalid_argument("The data passed to cryptvec must be larger than 0 bytes.");

    resize(len);
    for (int i = 0; i < len; i++)
    {
        (*this)[i] = data[i];
    }
}

/*
cryptvec::cryptvec(const std::string& data)
{
    resize(data.size());
    std::copy(data.begin(), data.end(), begin());
}
*/
cryptvec &cryptvec::operator^=(const cryptvec& other) {

    if (&other == this)
    {
        return *this;
    }

    for (int i = 0; i < size(); i++)
    {
        (*this)[i] = (*this)[i] ^ other[i % other.size()];
    }

    return *this;
}

cryptvec& cryptvec::operator^=(const uint8_t& other)
{
    for (unsigned char & it : *this)
    {
        it = it ^ other;
    }

    return *this;
}


cryptvec operator^(cryptvec lhs, const cryptvec& rhs)
{
    lhs ^= rhs;
    return lhs;
}


cryptvec operator^(const cryptvec& lhs, const uint8_t& other)
{
    cryptvec ret(lhs);

    for (int i = 0; i < lhs.size(); i++)
    {
        ret[i] = ret[i] ^ other;
    }

    return ret;
}

cryptvec& cryptvec::operator^=(const std::string& other)
{
    for (int i = 0; i < this->size(); i++)
    {
        (*this)[i] = (*this)[i] ^ other[i % other.size()];
    }

    return *this;
}

cryptvec operator^(cryptvec lhs, const std::string &rhs)
{
    lhs ^= rhs;
    return lhs;
}

template<typename T>
unsigned int cryptvec::distance(const T& other)
{
    if (other.size() != size())
        throw std::invalid_argument("The operator provided for hamming distance must match the size of the "
                                    "current value");

    return calc_hamming_distance(*this, other);
}


template cryptvec::cryptvec(const std::vector<uint8_t>& data);
template cryptvec::cryptvec(const std::string& data);

template unsigned int cryptvec::distance(const std::vector<uint8_t>& other);
template unsigned int cryptvec::distance(const std::string& other);
template unsigned int cryptvec::distance(const cryptvec& other);

