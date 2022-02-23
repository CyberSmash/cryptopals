//
// Created by jordan on 2/1/22.
//

#ifndef CRYPTOPALS_FILE_OPS_H
#define CRYPTOPALS_FILE_OPS_H

#include <vector>
using std::vector;
#include <string>
using std::string;

/**
 * Read a file line by line.
 * @param filename The file to read
 * @return A vector containing the individual lines of the file.
 */
vector<string> read_file_lines(string filename);

/**
 * Read in an entire file into a single string.
 *
 * TODO: This should be templated so we  can return binary data
 * in a vector<uint8_t> as well. Perhaps any iterable type?
 *
 * @param filename - The file to read.
 * @return A string with all the ascii data inside.
 */
std::string read_entire_file(string filename);

/**
 * Reads in base64 encoded data out of a file, and returns
 * the raw bytes in a vector.
 *
 * @param filename The file to open.
 * @return A vector of base64 decoded bytes.
 */
std::vector<uint8_t> read_base64_decode(const std::string& filename);

#endif //CRYPTOPALS_FILE_OPS_H
