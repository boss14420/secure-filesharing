/*
 * =====================================================================================
 *
 *       Filename:  file_encrypt.hh
 *
 *    Description:
 *
 *        Version:  1.0
 *        Created:  12/21/2014 02:33:24 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (),
 *   Organization:
 *
 * =====================================================================================
 */

#ifndef __ENCRYPT_HH__
#define __ENCRYPT_HH__

#include "include/config.hh"
#include "include/rsa.hpp"
#include "include/oaep.hpp"
#include "include/aes.hpp"
#include "securesharing.hh"

#include <cstdint>
#include <iosfwd>
#include <vector>
#include <unordered_map>

class FileEncrypt : public SecureSharing {
public:
    static const std::uint32_t HashSize = SecureSharing::HashSize;
    static const std::uint32_t AES_Keysize = SecureSharing::AES_Keysize;

    typedef rsa::RSAPublicKey<BigInt> RSAPublicKey;
    using SecureSharing::HashSHA3;
    using SecureSharing::MGF;
    typedef oaep::OAEP<MGF, RSAPublicKey> OAEP;

    using SecureSharing::AESBlock;
    using SecureSharing::AESKey;
    using SecureSharing::AES;

private:
    using SecureSharing::bytearray;

    std::uint32_t num_buckets;

    std::vector<std::vector<bytearray>> hash_table;
    std::vector<std::string> users;
    std::unordered_map<std::string, RSAPublicKey> rsa_publickeys;
    RSAPublicKey admin_key;


public:
    FileEncrypt(std::size_t RSA_Keysize, AESKey const& key,
                std::uint64_t nonce);

    void encrypt(std::istream &is, std::ostream &os);

    void write_header(std::ostream &os);
    void calculate_hashtable();
    void load_publickeys(std::string const &key_dir,
                            std::vector<std::string> const &users);

private:
    static std::size_t estimate_num_buckets(std::size_t num_elements);
};

#endif // __ENCRYPT_HH__
