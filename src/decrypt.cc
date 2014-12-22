/*
 * =====================================================================================
 *
 *       Filename:  decrypt.cc
 *
 *    Description:
 *
 *        Version:  1.0
 *        Created:  12/22/2014 11:41:05 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  boss14420, firefoxlinux at gmail dot com
 *   Organization:
 *
 * =====================================================================================
 */

#include "file_decrypt.hh"
#include <fstream>

int main(int argc, char *argv[])
{
    std::ostream *os;
    std::istream *is;
    std::cin.sync_with_stdio(false);
    std::cout.sync_with_stdio(false);

    if (argc < 4) {
        std::cerr << "Usage: "
            << argv[0] << " infile outfile username [keypath]\n";
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

    //////////////////////////////////////////
    //// setup key
    std::string username = argv[3], keypath;
    if (argc > 4) keypath = argv[4];
    else keypath = "keys/" + username + ".secretkey";

    //////////////////////////////////////////
    //// decrypt
    //
    FileDecrypt fd;
    try {
        fd.load_secretkey(keypath, username);
        fd.get_aeskey(*is);
    } catch (char const *s) {
        std::cerr << "Error: " << s << '\n';
        if (argv[2] != hyphen) delete os;
        if (argv[1] != hyphen) delete is;
        return -2;
    }
    fd.decrypt(*is, *os);

    if (argv[2] != hyphen) delete os;
    if (argv[1] != hyphen) delete is;

    return 0;
}
