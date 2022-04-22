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

    std::string to_string();

    /**
     * Initializes a cryptvec with data that is base64 encoded.
     *
     * This will initialize this vector by decoding the provided base64 encoded
     * data.
     *
     * TODO: Throws a invalid_parameter exception if the provided data is
     * empty. However, it might make more since to silently accept this
     * and resize the vector to 0 bytes. In addition if I'm going to
     * throw an exception, perhapse it makes sense to at least
     * need 3 bytes of data, as that would be the smallest possible
     * b64 encoding possible (i think).
     *
     * @param b64_data - The base64 encoded data.
     * @throws logic_error - If the base64 encoded
     * @throws invalid_parameter - If base64_data is zero bytes long.
     */
    static cryptvec base64_decode(const std::string& b64_data);

};



#endif //CRYPTOPALS_CRYPTVEC_H
