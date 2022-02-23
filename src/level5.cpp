#include <iostream>
#include <algorithm>

#include "helpers.hpp"
#include "file_ops.h"
#include "xor.hpp"
#include "ascii_analysis.h"
#include "cryptvec.h"
int main()
{
    cryptvec to_encode("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal");
    cryptvec key("ICE");
    cryptvec ct(to_encode ^ key);
    print_hex(ct);

}

