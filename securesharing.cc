/*
 * =====================================================================================
 *
 *       Filename:  securesharing.cc
 *
 *    Description:
 *
 *        Version:  1.0
 *        Created:  12/22/2014 10:05:13 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (),
 *   Organization:
 *
 * =====================================================================================
 */

#include "securesharing.hh"

constexpr char SecureSharing::magic_number[];

SecureSharing::SecureSharing(std::size_t RSA_Keysize, AESKey const& aeskey,
                            std::uint64_t nonce)
    : RSA_Keysize(RSA_Keysize), aeskey(aeskey), nonce(nonce)
{}

std::size_t SecureSharing::hash(std::string const &s)
{
    // djb2: http://www.cse.yorku.ca/~oz/hash.html
    std::size_t h = 5381;
    for (auto c : s) {
        h = (h * 33 + c);
    }
    return h;
}
