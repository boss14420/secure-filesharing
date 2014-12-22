/*
 * =====================================================================================
 *
 *       Filename:  aes.cc
 *
 *    Description:
 *
 *        Version:  1.0
 *        Created:  12/21/2014 06:14:47 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (),
 *   Organization:
 *
 * =====================================================================================
 */


#include "include/aes.hpp"

namespace aes {
namespace internal {

template <>
void AES_key_expand<128>(typename AES_traits<128>::Key const &key,
        typename AES_traits<128>::ExpandedKey &expandedKey) {
    using std::uint32_t;
    using internal::sbox;
    std::memcpy(expandedKey.data(), key.data(), 16);
    auto kep = expandedKey.data() + 16;
    for (int i = 1; i < AES_traits<128>::nround + 1; ++i) {
        *kep = kep[-16] ^ sbox[kep[-3]] ^ rcon[i];
        kep[1] = kep[-15] ^ sbox[kep[-2]];
        kep[2] = kep[-14] ^ sbox[kep[-1]];
        kep[3] = kep[-13] ^ sbox[kep[-4]];

        *(uint32_t*) (kep + 4) = *(uint32_t*) (kep - 12) ^ *(uint32_t*) (kep);
        *(uint32_t*) (kep + 8) = *(uint32_t*) (kep - 8) ^ *(uint32_t*) (kep + 4);
        *(uint32_t*) (kep + 12) = *(uint32_t*) (kep - 4) ^ *(uint32_t*) (kep + 8);

        kep += 16;
    }
}

} // namespace internal
} // namespace aes
