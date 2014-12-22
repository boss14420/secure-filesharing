/*
 * =====================================================================================
 *
 *       Filename:  securesharing.hh
 *
 *    Description:
 *
 *        Version:  1.0
 *        Created:  12/21/2014 02:19:01 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (),
 *   Organization:
 *
 * =====================================================================================
 */

#ifndef __SECURE_SHARING_HH__
#define __SECURE_SHARING_HH__

#include "include/config.hh"
#include "include/oaep.hpp"
#include "include/aes.hpp"

// FILE info
class SecureSharing {
public:
    static const std::uint32_t HashSize = 256;
    static const std::uint32_t AES_Keysize = 128;

    typedef oaep::HashSHA3<HashSize> HashSHA3;
    typedef oaep::MGF1<HashSHA3> MGF;

    typedef aes::AES<AES_Keysize> AESBlock;
    typedef AESBlock::Key AESKey;
    typedef aes::AES_CTRMode<AES_Keysize> AES;

//protected:
    typedef std::vector<std::uint8_t> bytearray;
    static const char magic_number[4];

    std::uint32_t RSA_Keysize;
    AESKey aeskey;
    std::uint64_t nonce;

public:
    SecureSharing() = default;
    SecureSharing(std::size_t RSA_Keysize, AESKey const& aeskey,
                    std::uint64_t nonce);

protected:
    static std::size_t hash(std::string const &s);
};

#endif // __SECURE_SHARING_HH__
