/*
 * =====================================================================================
 *
 *       Filename:  file_encrypt.cc
 *
 *    Description:
 *
 *        Version:  1.0
 *        Created:  12/21/2014 01:59:56 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  BOSS14420
 *   Organization:
 *
 * =====================================================================================
 */


#include <cstdio>
#include <cstdint>
#include <fstream>
#include <algorithm>
#include "file_encrypt.hh"
#include "include/integer.hpp"

FileEncrypt::FileEncrypt(std::size_t RSA_Keysize, AESKey const& aeskey,
                            std::uint64_t nonce)
    : SecureSharing(RSA_Keysize, aeskey, nonce)
{
}

void FileEncrypt::write_header(std::ostream &os)
{
    os.write(magic_number, sizeof(magic_number)); // 4 bytes
    char bytes[4];
    std::size_t metadata = sizeof(magic_number) + 20;
    std::size_t header_size = metadata + RSA_Keysize / 8 + 4 * (num_buckets + 2);
    for (auto bucket : hash_table)
        header_size += bucket.size() * RSA_Keysize / 8;
    os.write(integer::int_to_bytes<std::uint32_t>(bytes, header_size), 4);
    os.write(integer::int_to_bytes<std::uint32_t>(bytes, metadata), 4);
    os.write(integer::int_to_bytes<std::uint32_t>(bytes, RSA_Keysize), 4);
    os.write(integer::int_to_bytes<std::uint32_t>(bytes, HashSize), 4);
    os.write(integer::int_to_bytes<std::uint32_t>(bytes, AES_Keysize), 4);

    std::vector<std::uint8_t> oaep_ciphertext(RSA_Keysize/8);
    OAEP(admin_key).encrypt(aeskey.data(), AES_Keysize/8, oaep_ciphertext.data());
    os.write((char const *)oaep_ciphertext.data(), RSA_Keysize / 8);

    os.write(integer::int_to_bytes<std::uint32_t>(bytes, num_buckets), 4);

    ///////////////////////////////
    ////// bucket offsets
    //
    std::size_t offset = 0;
    // offset of bucket 0
    os.write(integer::int_to_bytes<std::uint32_t>(bytes, offset), 4);
    for (std::size_t i = 0; i != num_buckets; ++i) {
        offset += hash_table[i].size();
        // write end offset of bucket i
        os.write(integer::int_to_bytes<std::uint32_t>(bytes, offset), 4);
    }

    ///////////////////////////////
    ////// write buckets
    //
    for (std::size_t i = 0; i != num_buckets; ++i) {
        for(auto &ciphertext : hash_table[i]) {
            os.write((char const *)&ciphertext[0], RSA_Keysize/8);
        }
    }
}


void FileEncrypt::calculate_hashtable()
{
    num_buckets = estimate_num_buckets(rsa_publickeys.size());
    hash_table.resize(num_buckets);

    bytearray oaep_message(HashSize / 8 + AES_Keysize / 8);
    std::copy_n(aeskey.begin(), AES_Keysize / 8, oaep_message.begin() + HashSize / 8);

    for (auto &user : users) {
        if (rsa_publickeys.find(user) == rsa_publickeys.end())
            continue;

        std::size_t bucket = SecureSharing::hash(user) % num_buckets;

        // OAEP encrypt ( hash(user) || aes_key)
        OAEP oaep(rsa_publickeys[user]);
        HashSHA3()((std::uint8_t*)user.data(), user.size(), oaep_message.data());
        bytearray oaep_ciphertext(RSA_Keysize / 8);
        oaep.encrypt(oaep_message.data(), oaep_message.size(),
                     oaep_ciphertext.data());

        hash_table[bucket].emplace_back(std::move(oaep_ciphertext));
    }

    // add dummy ciphertext to empty buckets
    bytearray dummy(RSA_Keysize / 8);
    for (auto &buckets : hash_table) {
        if (buckets.size() == 0) {
            util::urandom(dummy.data(), dummy.size());
            buckets.push_back(dummy);
        }
    }
}

std::size_t FileEncrypt::estimate_num_buckets(std::size_t num_elements)
{
    std::size_t num_slots = num_elements / 0.75f;

    static const std::size_t primes[] = {
        7, 11, 23, 53, 107, 181, 257, 307, 359, 409, 461, 521,
        563, 617, 661, 719, 773, 821, 877, 919, 967, 1031
    };
    static const std::size_t ps = sizeof(primes) / sizeof(std::size_t);

    // TODO: arbitrary large num_slots
    if (num_slots > primes[ps-1]) return num_slots;

    return *std::upper_bound(primes, primes + ps, num_slots);
}

void FileEncrypt::load_publickeys(std::string const &key_dir,
                        std::vector<std::string> const &users)
{
    this->users = users;

    // load admin key
    std::ifstream ifs((key_dir + "admin.publickey").c_str());
    if (!ifs)
        throw "Cannot read admin's public key";
    ifs >> admin_key;
    ifs.close();

    for (auto &user : users) {
        ifs.open((key_dir + user + ".publickey").c_str());
        if (!ifs) continue;
        ifs >> rsa_publickeys[user];
        if (rsa_publickeys[user].keysize() != RSA_Keysize)
            rsa_publickeys.erase(rsa_publickeys.find(user));
        ifs.close();
    }
}


void FileEncrypt::encrypt(std::istream& is, std::ostream& os)
{
    auto p = std::get_temporary_buffer<std::uint8_t>(AESBlock::block_size * 500000);
    auto p2 = std::get_temporary_buffer<std::uint8_t>(AESBlock::block_size * 500000);
    AES aes(aeskey, nonce);
    os.write(integer::int_to_bytes<std::uint64_t>((char*)p.first, nonce), 8);
    while (!is.eof()) {
        is.read((char *)p.first, p.second);
        auto read = is.gcount();
        if (!read) break;
        auto p2end = aes.encrypt_append(p.first, p.first + read, p2.first);
        os.write((char *)p2.first, p2end - p2.first);
    }
    auto p2end = aes.encrypt_finish(p.first, p.first, p2.first);
    os.write((char *)p2.first, p2end - p2.first);

    std::return_temporary_buffer(p.first);
    std::return_temporary_buffer(p2.first);
}
