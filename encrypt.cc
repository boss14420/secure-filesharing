/*
 * =====================================================================================
 *
 *       Filename:  encrypt.cc
 *
 *    Description:
 *
 *        Version:  1.0
 *        Created:  12/21/2014 05:25:22 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (),
 *   Organization:
 *
 * =====================================================================================
 */


#include "include/util.hpp"
#include "file_encrypt.hh"
#include <fstream>

int main(int argc, char *argv[])
{
    std::ostream *os;
    std::istream *is;
    std::cin.sync_with_stdio(false);
    std::cout.sync_with_stdio(false);

    if (argc < 4) {
        std::cerr << "Usage: "
            << argv[0] << " infile outfile [-d keypath] KEYS\n";
        return -1;
    }

    /////////////////////////////////////////
    //// setup streams
    std::string hyphen("-");

    if (argv[1] != hyphen) {
        is = new std::ifstream(argv[1],
                std::ios::in | std::ios::binary);
        if (!*is) {
            std::cerr << "Cannot open " << argv[1] << '\n';
            return -3;
        }
    } else is = &std::cin;

    if (argv[2] != hyphen) {
        os = new std::ofstream(argv[2],
                std::ios::out | std::ios::binary);
        if (!*os) {
            std::cerr << "Cannot open " << argv[2] << '\n';
            if (argv[1] != hyphen) delete is;
            return -3;
        }
    } else os = &std::cout;

    //////////////////////////////////////
    //// setup keys
    int userargc = 3;
    std::string keypath;
    if (std::string(argv[3]) == "-d") {
        if (argc < 5) {
            std::cerr << "Missing keypath\n";
            if (argv[2] != hyphen) delete os;
            if (argv[1] != hyphen) delete is;
            return -1;
        }
        keypath = argv[4];
        userargc = 5;
    } else keypath = "keys/";

    std::vector<std::string> users;
    for (; userargc < argc; ++userargc)
        users.emplace_back(argv[userargc]);

    // generate random aes key & nonce
    FileEncrypt::AESKey aeskey;
    util::urandom(aeskey.data(), FileEncrypt::AES_Keysize/8);
    std::uint64_t nonce;
    util::urandom((std::uint8_t*)&nonce, 8);

    FileEncrypt fe(6144, aeskey, nonce);

    try {
        fe.load_publickeys(keypath, users);
        fe.calculate_hashtable();
    } catch (char const *s) {
        std::cerr << "Error: " << s << '\n';
        if (argv[2] != hyphen) delete os;
        if (argv[1] != hyphen) delete is;
        return -2;
    }

    fe.write_header(*os);
    fe.encrypt(*is, *os);

    if (argv[2] != hyphen) delete os;
    if (argv[1] != hyphen) delete is;

    return 0;
}
