/*
 * =====================================================================================
 *
 *       Filename:  oaep.hpp
 *
 *    Description:
 *
 *        Version:  1.0
 *        Created:  12/20/2014 08:47:45 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  BOSS 14420
 *   Organization:
 *
 * =====================================================================================
 */

#ifndef __OAEP_HPP__
#define __OAEP_HPP__

#include <cstdint>
#include <vector>
#include <algorithm>
#include <functional>

#include "util.hpp"
#include "sha3.hpp"
#include "rsa.hpp"

namespace oaep {

typedef std::uint8_t byte;
typedef std::vector<byte> bytearray;

/////////////////////////////////////////////////////////////////////
//////// OAEP
// Key = RSAKey OR Key = RSAPublicKey
//
template <typename MGFFunc, typename Key>
class OAEP {
public:
    typedef typename Key::Integer Integer;

private:
    Key const key;
    std::size_t const k;
    MGFFunc const mgf;
    bytearray lHash;

public:
    template <typename Key2>
    OAEP(Key2 &&key)
        : key(std::move(key)), k(key.keysize() / 8),
          mgf(), lHash(mgf.hLen())
    {
        // lHash = mgf.hash(EMPTY STRING)
        mgf.hash(nullptr, 0, lHash.data());
    }

    std::size_t max_message_len() const {
        return k - 2*mgf.hLen() - 2;
    }

    std::size_t key_size() const { return k * 8; }

    byte* encrypt(byte* M, std::size_t mLen, byte *cipher) const
    {
        // length checking
        if (mLen > k - 2*mgf.hLen() - 2)
            throw "message too long";
        bytearray EM(k);
        pad(M, mLen, EM.data());

        auto m = bigint::bytes_to_int<Integer>(EM.data(), k);
        auto c = key.encrypt_int(m);
        return bigint::int_to_bytes(c, cipher, k);
    }

    std::pair<byte*, std::size_t> decrypt(byte* C, std::size_t cLen, byte *plain) const
    {
        if (cLen != k)
            throw "decryption error";
        // TODO: assert(c < modulus)
        auto c = bigint::bytes_to_int<Integer>(C, k);
        auto m = key.decrypt_int(c);
        bytearray EM(k);
        bigint::int_to_bytes(m, EM.data(), k);
        return unpad(EM.data(), plain);
    }

private:
    // OAEP padding
    void pad(byte const *M, std::size_t mLen, byte *EM) const
    {
        using std::begin;
        using std::end;

        // length checking
//        if (mLen > k - 2*mgf.hLen() - 2)
//            throw "message too long";

        // DB = (lHash || PS || 0x01 || M) XOR MGF(seed)
        byte *DB = EM + 1 + mgf.hLen();
        std::copy(&lHash[0], &lHash[mgf.hLen()], DB);
        std::fill_n(DB + mgf.hLen(), k - mLen - 2*mgf.hLen() - 2, 0);
        DB[k - mgf.hLen() - 1 - mLen - 1] = 0x01;
        std::copy(M, M + mLen, DB + k - mgf.hLen() - 1 - mLen);

        bytearray dbMask(k - mgf.hLen() - 1);
        byte *seed = EM + 1;
        util::urandom(seed, mgf.hLen());
        mgf(seed, mgf.hLen(), dbMask.data(), k - mgf.hLen() - 1);
        std::transform(DB, DB + k - mgf.hLen() - 1, begin(dbMask),
                        DB, std::bit_xor<byte>());

        // seed <- seed XOR MGF(DB)
        bytearray seedMask(mgf.hLen());
        mgf(DB, k - mgf.hLen() - 1, seedMask.data(), mgf.hLen());
        std::transform(seed, seed + mgf.hLen(), begin(seedMask),
                        seed, std::bit_xor<byte>());

        EM[0] = 0x00;
    }

    // OAEP unpad
    std::pair<byte*, std::size_t> unpad(byte *EM, byte *M) const
    {
        using std::begin;
        auto Y = EM, maskedSeed = EM + 1,
             maskedDB = maskedSeed + mgf.hLen();

        // seed = seedMask XOR maskedSeed = mgf(maskedDB, hLen) XOR maskedSeed
        bytearray seedMask(mgf.hLen());
        auto seed = maskedSeed;
        mgf(maskedDB, k - mgf.hLen() - 1, seedMask.data(), mgf.hLen());
        std::transform(maskedSeed, maskedSeed + mgf.hLen(), begin(seedMask),
                       seed, std::bit_xor<byte>());

        // db = maskedDB XOR dbMask
        bytearray dbMask(k - mgf.hLen() - 1);
        auto DB = maskedDB;
        mgf(seed, mgf.hLen(), dbMask.data(), k - mgf.hLen() - 1);
        std::transform(maskedDB, maskedDB + k - mgf.hLen() - 1, begin(dbMask),
                       DB, std::bit_xor<byte>());

        // check
        auto lHash2 = DB, PS = DB + mgf.hLen();

        bool error = false;
        if (!std::equal(begin(lHash), end(lHash), lHash2)) error = true;
        if (*Y != 0) error = true;

        auto p = PS;
        byte *sep = nullptr;
        while (p != PS + k - 2*mgf.hLen() - 1) {
            if (*p != 0) {
                sep = sep ? sep : p;
            }
            ++p;
        }
        if(*sep != 1) error = true;

        if (error) throw "decryption error";

        auto mLen = std::copy(sep + 1, PS + k - 2*mgf.hLen() - 1, M) - M;
        return std::make_pair(M, mLen);
    }
};

/////////////////////////////////////////////////////////////////////
//////// MGF1: Mask Generation Function
//
template <typename HashFunc>
class MGF1
{
    HashFunc _hash;

public:
    byte* operator()(byte *seed, std::size_t sLen,
                    byte *mask, std::size_t mLen) const
    {
        using std::begin;

        if (mLen > (1ULL << 32) * hLen())
            throw "mask too long";

        std::vector <byte> hashInput(sLen + 4);
        std::copy(seed, seed + sLen, begin(hashInput));
        auto C = begin(hashInput) + sLen;

        auto loop = std::ceil(mLen * 1./ hLen());
        std::vector <byte> _digest(hLen() * loop);
        byte *digest = _digest.data();

        for (std::uint32_t counter = 0; counter != loop; ++counter, digest += hLen()) {
            C[0] = counter >> 24; C[1] = counter >> 16;
            C[2] = counter >>  8; C[3] = counter;

            _hash(hashInput.data(), sLen + 4, digest);
        }

        std::copy(begin(_digest), begin(_digest) + mLen, mask);
        return mask;
    }

    std::size_t hLen() const { return _hash.hashLen(); }

    byte *hash(byte const *message, std::size_t len,
                       byte *digest) const
    {
        return _hash(message, len, digest);
    }
};

/////////////////////////////////////////////////////////////////////
//////// Hash using SHA3
//
template <int HashSize>
class HashSHA3
{
public:
    byte *operator()(byte const *message, std::size_t len,
                                byte *digest) const
    {
        SHA3<HashSize>((char const*)message, len).digest((char*)digest);
        return digest;
    }

    std::size_t hashLen() const { return HashSize / 8; }
};

} // namespace oaep
#endif // __OAEP_HPP__
