/*
 * =====================================================================================
 *
 *       Filename:  file_decrypt.hh
 *
 *    Description:
 *
 *        Version:  1.0
 *        Created:  12/22/2014 10:34:52 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Boss14420 (), firefox at gmail dot com
 *   Organization:
 *
 * =====================================================================================
 */

#ifndef __FILE_DECRYPT_HH__
#define __FILE_DECRYPT_HH__

#include "include/config.hh"
#include "include/rsa.hpp"
#include "include/oaep.hpp"
#include "include/aes.hpp"
#include "securesharing.hh"

#include <cstdint>
#include <iosfwd>
#include <vector>
#include <unordered_map>

class FileDecrypt : public SecureSharing {
public:
    static const std::uint32_t HashSize = SecureSharing::HashSize;
    static const std::uint32_t AES_Keysize = SecureSharing::AES_Keysize;

    typedef rsa::RSAKey<BigInt> RSAKey;
    using SecureSharing::HashSHA3;
    using SecureSharing::MGF;
    typedef oaep::OAEP<MGF, RSAKey> OAEP;

    using SecureSharing::AESBlock;
    using SecureSharing::AESKey;
    using SecureSharing::AES;

//private:
    using SecureSharing::bytearray;

    RSAKey rsa_secretkey;
    std::string username;

public:
    FileDecrypt();

    void decrypt(std::istream &is, std::ostream &os);

//private:
    void get_aeskey(std::istream &is);
    void load_secretkey(std::string const &keypath, std::string const &name);
};


#endif // __FILE_DECRYPT_HH__
