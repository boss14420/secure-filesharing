/*
 * =====================================================================================
 *
 *       Filename:  file_decrypt.cc
 *
 *    Description:
 *
 *        Version:  1.0
 *        Created:  12/22/2014 10:39:23 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  BOSS14420 (), firefoxlinux at gmail dot com
 *   Organization:
 *
 * =====================================================================================
 */


#include <cstdio>
#include <cstdint>
#include <fstream>
#include <algorithm>
#include "file_decrypt.hh"
#include "include/integer.hpp"

FileDecrypt::FileDecrypt() {}

/////////////////////////////////////////////////////////
//// get aeskey & skip to aes stream
//
void FileDecrypt::get_aeskey(std::istream &is)
{
    char bytes[8];
    is.read(bytes, sizeof(magic_number));
    if (!std::equal(bytes, bytes + sizeof(magic_number), magic_number))
        throw "Not valid encrypted file";

    // metadata
    std::uint32_t header_size, metadata;
    is.read(bytes, 4);
    header_size = integer::bytes_to_int<std::uint32_t>(bytes);
    is.read(bytes, 4);
    metadata = integer::bytes_to_int<std::uint32_t>(bytes);

    is.read(bytes, 4);
    RSA_Keysize = integer::bytes_to_int<std::uint32_t>(bytes);
    if (rsa_secretkey.keysize() != RSA_Keysize) {
        throw "Cannot find aeskey";
    }

    is.read(bytes, 4); // HashSize
    is.read(bytes, 4); // AES_Keysize

    // read entire header
    bytearray headers(header_size - metadata);
    is.read((char*)headers.data(), header_size - metadata);
    auto hpointer = headers.data();

    // skip admin oaep ciphertext of aeskey
    hpointer += RSA_Keysize/8;


    ///////////////////////////////////////////////////////////
    //// find oaep ciphertext slot for my rsa key
    //
    std::uint32_t num_buckets;
    num_buckets = integer::bytes_to_int<std::uint32_t>((char*)hpointer);
    hpointer += 4;

    auto bucket = SecureSharing::hash(username) % num_buckets;
    hpointer += 4 * bucket;
    std::uint32_t bucket_begin_off, bucket_end_off;
    bucket_begin_off = integer::bytes_to_int<std::uint32_t>((char*)hpointer);
    hpointer += 4;
    bucket_end_off = integer::bytes_to_int<std::uint32_t>((char*)hpointer);
    hpointer += 4;

    if (bucket_begin_off == bucket_end_off)
        throw "Cannot find aeskey";

    // skip to bucket
    hpointer += 4 * (num_buckets - bucket - 1);
    hpointer += RSA_Keysize / 8 * bucket_begin_off;

    // search
    bytearray userhash(HashSize / 8);
    HashSHA3()((std::uint8_t*) username.data(), username.size(),
                userhash.data());

    OAEP oaep(rsa_secretkey);
    bytearray oaep_plaintext(RSA_Keysize/8);

    // TODO: resistance to timing attack
    bool found = false;
    for (auto i = bucket_begin_off; i != bucket_end_off; ++i) {
        std::size_t size;
        try {
            size = oaep.decrypt(hpointer, RSA_Keysize/8,
                                oaep_plaintext.data()).second;
        } catch (char const *) {
            hpointer += RSA_Keysize/8;
            continue;
        }
        hpointer += RSA_Keysize/8;
        if (size != AES_Keysize / 8 + HashSize / 8)
            continue;
        if (!std::equal(userhash.begin(), userhash.end(), oaep_plaintext.begin()))
            continue;

        std::copy_n(oaep_plaintext.begin() + HashSize/8, AES_Keysize/8, aeskey.data());
        found = true;
        break;
    }
    if (!found)
        throw "Cannot find aeskey";
}


/////////////////////////////////////////////////////////
//// load secretkey from file
//
void FileDecrypt::load_secretkey(std::string const &keypath,
                                    std::string const &name)
{
    username = name;
    std::ifstream ifs(keypath);
    if (!ifs)
        throw "Cannot read secret key";
    ifs >> rsa_secretkey;
    ifs.close();
}


/////////////////////////////////////////////////////////
//// decrypt
//
void FileDecrypt::decrypt(std::istream& is, std::ostream& os)
{
    // read nonce
    char bytes[8];
    is.read(bytes, 8);
    nonce = integer::bytes_to_int<std::uint64_t>(bytes);

    // decrypt aes
    auto p = std::get_temporary_buffer<std::uint8_t>(AESBlock::block_size * 500000);
    auto p2 = std::get_temporary_buffer<std::uint8_t>(AESBlock::block_size * 500000);
    decltype(p2.first) p2end;
    AES aes(aeskey, nonce);
    while (true) {
        is.read((char *)p.first, p.second);
        auto read = is.gcount();
        if(is.peek() == EOF) {
            p2end = aes.decrypt_finish(p.first, p.first + read, p2.first);
            break;
        } else
            p2end = aes.decrypt_append(p.first, p.first + read, p2.first);
        os.write((char *)p2.first, p2end - p2.first);
    }
    os.write((char *)p2.first, p2end - p2.first);

    std::return_temporary_buffer(p.first);
    std::return_temporary_buffer(p2.first);
}
