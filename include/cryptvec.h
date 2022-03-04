//
// Created by Jordan Sebastian on 2/15/22.
//

#ifndef CRYPTOPALS_CRYPTVEC_H
#define CRYPTOPALS_CRYPTVEC_H
#include <vector>
#include <iostream>
using std::vector;

class cryptvec : public vector<uint8_t>  {
    using vector::vector;
public:
    template <typename T>
    explicit cryptvec(const T& data);
    explicit cryptvec(const char* data);
    explicit cryptvec(int size);


    cryptvec& operator^=(const cryptvec& other);
    cryptvec& operator^=(const std::string& other);
    cryptvec& operator^=(const uint8_t& other);

    friend cryptvec operator^(cryptvec lhs, const cryptvec& rhs);
    friend cryptvec operator^(const cryptvec& lhs, const uint8_t& other);
    friend cryptvec operator^(cryptvec lhs, const std::string& rhs);
    friend std::ostream& operator<<(std::ostream& os, const cryptvec& cv);
    template<typename T>
    unsigned int distance(const T& other);

};



#endif //CRYPTOPALS_CRYPTVEC_H
