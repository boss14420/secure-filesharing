/*
 * =====================================================================================
 *
 *       Filename:  rsa_genkey.cc
 *
 *    Description:
 *
 *        Version:  1.0
 *        Created:  12/21/2014 03:20:10 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (),
 *   Organization:
 *
 * =====================================================================================
 */

#include "include/config.hh"

#include <fstream>
#include <iostream>
#include "include/rsa.hpp"

int main(int argc, char *argv[])
{
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " key_len name\n";
        return 1;
    }

    long keysize = std::atol(argv[1]);
    if (keysize <= 0 || keysize % 16 != 0) {
        std::cerr << "Invalid keysize: " << argv[1] << '\n';
    }
    auto key = rsa::generate_rsakey<BigInt>(keysize);

    // secret key
    std::ofstream of(std::string(argv[2]) + ".secretkey");
    of << key << '\n';
    of.close();

    // public key
    of.open(std::string(argv[2]) + ".publickey");
    of << key.public_key() << '\n';
    of.close();

    return 0;
}

