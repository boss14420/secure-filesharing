/*
 * =====================================================================================
 *
 *       Filename:  aes.hpp
 *
 *    Description:
 *
 *        Version:  1.0
 *        Created:  12/18/2014 10:29:13 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (),
 *   Organization:
 *
 * =====================================================================================
 */

#ifndef AES_HPP
#define	AES_HPP


#include <array>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <utility>

namespace aes {
namespace internal {
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////

struct AES_traits_base {
    //    typedef std::array<unsigned char, 16 > RoundKey;
    typedef unsigned char const * RoundKey;
    typedef std::array<unsigned char, 16> State;
};

template <int KeySize> struct AES_traits;

template <> struct AES_traits<128> : public AES_traits_base {
    static const int key_size = 128;
    static const int nround = 10;
    static const int block_size = 16;
    typedef std::array<unsigned char, key_size / 8 > Key;
    typedef std::array<unsigned char, 16 * (nround + 1) > ExpandedKey;
};

//////////////////////////////////////////////////////////////////
/////// constants ////////////////////////////////////////////////

static const unsigned char gmul2[256] = {
    0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e,
    0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e, 0x30, 0x32, 0x34, 0x36, 0x38, 0x3a, 0x3c, 0x3e,
    0x40, 0x42, 0x44, 0x46, 0x48, 0x4a, 0x4c, 0x4e, 0x50, 0x52, 0x54, 0x56, 0x58, 0x5a, 0x5c, 0x5e,
    0x60, 0x62, 0x64, 0x66, 0x68, 0x6a, 0x6c, 0x6e, 0x70, 0x72, 0x74, 0x76, 0x78, 0x7a, 0x7c, 0x7e,
    0x80, 0x82, 0x84, 0x86, 0x88, 0x8a, 0x8c, 0x8e, 0x90, 0x92, 0x94, 0x96, 0x98, 0x9a, 0x9c, 0x9e,
    0xa0, 0xa2, 0xa4, 0xa6, 0xa8, 0xaa, 0xac, 0xae, 0xb0, 0xb2, 0xb4, 0xb6, 0xb8, 0xba, 0xbc, 0xbe,
    0xc0, 0xc2, 0xc4, 0xc6, 0xc8, 0xca, 0xcc, 0xce, 0xd0, 0xd2, 0xd4, 0xd6, 0xd8, 0xda, 0xdc, 0xde,
    0xe0, 0xe2, 0xe4, 0xe6, 0xe8, 0xea, 0xec, 0xee, 0xf0, 0xf2, 0xf4, 0xf6, 0xf8, 0xfa, 0xfc, 0xfe,
    0x1b, 0x19, 0x1f, 0x1d, 0x13, 0x11, 0x17, 0x15, 0x0b, 0x09, 0x0f, 0x0d, 0x03, 0x01, 0x07, 0x05,
    0x3b, 0x39, 0x3f, 0x3d, 0x33, 0x31, 0x37, 0x35, 0x2b, 0x29, 0x2f, 0x2d, 0x23, 0x21, 0x27, 0x25,
    0x5b, 0x59, 0x5f, 0x5d, 0x53, 0x51, 0x57, 0x55, 0x4b, 0x49, 0x4f, 0x4d, 0x43, 0x41, 0x47, 0x45,
    0x7b, 0x79, 0x7f, 0x7d, 0x73, 0x71, 0x77, 0x75, 0x6b, 0x69, 0x6f, 0x6d, 0x63, 0x61, 0x67, 0x65,
    0x9b, 0x99, 0x9f, 0x9d, 0x93, 0x91, 0x97, 0x95, 0x8b, 0x89, 0x8f, 0x8d, 0x83, 0x81, 0x87, 0x85,
    0xbb, 0xb9, 0xbf, 0xbd, 0xb3, 0xb1, 0xb7, 0xb5, 0xab, 0xa9, 0xaf, 0xad, 0xa3, 0xa1, 0xa7, 0xa5,
    0xdb, 0xd9, 0xdf, 0xdd, 0xd3, 0xd1, 0xd7, 0xd5, 0xcb, 0xc9, 0xcf, 0xcd, 0xc3, 0xc1, 0xc7, 0xc5,
    0xfb, 0xf9, 0xff, 0xfd, 0xf3, 0xf1, 0xf7, 0xf5, 0xeb, 0xe9, 0xef, 0xed, 0xe3, 0xe1, 0xe7, 0xe5
};

static const unsigned char gmul3[256] = {
    0x00,0x03,0x06,0x05,0x0c,0x0f,0x0a,0x09,0x18,0x1b,0x1e,0x1d,0x14,0x17,0x12,0x11,
    0x30,0x33,0x36,0x35,0x3c,0x3f,0x3a,0x39,0x28,0x2b,0x2e,0x2d,0x24,0x27,0x22,0x21,
    0x60,0x63,0x66,0x65,0x6c,0x6f,0x6a,0x69,0x78,0x7b,0x7e,0x7d,0x74,0x77,0x72,0x71,
    0x50,0x53,0x56,0x55,0x5c,0x5f,0x5a,0x59,0x48,0x4b,0x4e,0x4d,0x44,0x47,0x42,0x41,
    0xc0,0xc3,0xc6,0xc5,0xcc,0xcf,0xca,0xc9,0xd8,0xdb,0xde,0xdd,0xd4,0xd7,0xd2,0xd1,
    0xf0,0xf3,0xf6,0xf5,0xfc,0xff,0xfa,0xf9,0xe8,0xeb,0xee,0xed,0xe4,0xe7,0xe2,0xe1,
    0xa0,0xa3,0xa6,0xa5,0xac,0xaf,0xaa,0xa9,0xb8,0xbb,0xbe,0xbd,0xb4,0xb7,0xb2,0xb1,
    0x90,0x93,0x96,0x95,0x9c,0x9f,0x9a,0x99,0x88,0x8b,0x8e,0x8d,0x84,0x87,0x82,0x81,
    0x9b,0x98,0x9d,0x9e,0x97,0x94,0x91,0x92,0x83,0x80,0x85,0x86,0x8f,0x8c,0x89,0x8a,
    0xab,0xa8,0xad,0xae,0xa7,0xa4,0xa1,0xa2,0xb3,0xb0,0xb5,0xb6,0xbf,0xbc,0xb9,0xba,
    0xfb,0xf8,0xfd,0xfe,0xf7,0xf4,0xf1,0xf2,0xe3,0xe0,0xe5,0xe6,0xef,0xec,0xe9,0xea,
    0xcb,0xc8,0xcd,0xce,0xc7,0xc4,0xc1,0xc2,0xd3,0xd0,0xd5,0xd6,0xdf,0xdc,0xd9,0xda,
    0x5b,0x58,0x5d,0x5e,0x57,0x54,0x51,0x52,0x43,0x40,0x45,0x46,0x4f,0x4c,0x49,0x4a,
    0x6b,0x68,0x6d,0x6e,0x67,0x64,0x61,0x62,0x73,0x70,0x75,0x76,0x7f,0x7c,0x79,0x7a,
    0x3b,0x38,0x3d,0x3e,0x37,0x34,0x31,0x32,0x23,0x20,0x25,0x26,0x2f,0x2c,0x29,0x2a,
    0x0b,0x08,0x0d,0x0e,0x07,0x04,0x01,0x02,0x13,0x10,0x15,0x16,0x1f,0x1c,0x19,0x1a
};

static const unsigned char sbox[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

static const unsigned char rcon[] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a
};

//////////////////////////////////////////////////////////////////
/////// helpers //////////////////////////////////////////////////
template <int KeySize>
void AES_key_expand(typename AES_traits<KeySize>::Key const &key,
        typename AES_traits<KeySize>::ExpandedKey &expandedKey);

////////////////////////////////////////////////////////////////////////////////////////
////////// encrypt

// Subs byte
template <typename DataArrayIn, typename DataArrayOut>
static void substitute(DataArrayIn const &in, DataArrayOut &&out)
{
    out[0] = sbox[in[0]]; out[1] = sbox[in[1]]; out[2] = sbox[in[2]]; out[3] = sbox[in[3]];
    out[4] = sbox[in[4]]; out[5] = sbox[in[5]]; out[6] = sbox[in[6]]; out[7] = sbox[in[7]];
    out[8] = sbox[in[8]]; out[9] = sbox[in[9]]; out[10] = sbox[in[10]]; out[11] = sbox[in[11]];
    out[12] = sbox[in[12]]; out[13] = sbox[in[13]]; out[14] = sbox[in[14]]; out[15] = sbox[in[15]];
}

// shift rows
template <typename DataArrayIn, typename DataArrayOut>
static void shift_rows(DataArrayIn const &in, DataArrayOut &&out)
{
    out[0] = in[0], out[1] = in[5], out[2] = in[10], out[3] = in[15];
    out[4] = in[4], out[5] = in[9], out[6] = in[14], out[7] = in[3];
    out[8] = in[8], out[9] = in[13], out[10] = in[2], out[11] = in[7];
    out[12] = in[12], out[13] = in[1], out[14] = in[6], out[15] = in[11];
}

// mix columns
template <typename DataArrayIn, typename DataArrayOut>
static void mix_columns(DataArrayIn const &in, DataArrayOut &&out)
{
    out[0] = gmul2[in[0]] ^ gmul3[in[1]] ^ in[2] ^ in[3];
    out[1] = in[0] ^ gmul2[in[1]] ^ gmul3[in[2]] ^ in[3];
    out[2] = in[0] ^ in[1] ^ gmul2[in[2]] ^ gmul3[in[3]];
    out[3] = gmul3[in[0]] ^ in[1] ^ in[2] ^ gmul2[in[3]];
    out[4] = gmul2[in[4]] ^ gmul3[in[5]] ^ in[6] ^ in[7];
    out[5] = in[4] ^ gmul2[in[5]] ^ gmul3[in[6]] ^ in[7];
    out[6] = in[4] ^ in[5] ^ gmul2[in[6]] ^ gmul3[in[7]];
    out[7] = gmul3[in[4]] ^ in[5] ^ in[6] ^ gmul2[in[7]];
    out[8] = gmul2[in[8]] ^ gmul3[in[9]] ^ in[10] ^ in[11];
    out[9] = in[8] ^ gmul2[in[9]] ^ gmul3[in[10]] ^ in[11];
    out[10] = in[8] ^ in[9] ^ gmul2[in[10]] ^ gmul3[in[11]];
    out[11] = gmul3[in[8]] ^ in[9] ^ in[10] ^ gmul2[in[11]];
    out[12] = gmul2[in[12]] ^ gmul3[in[13]] ^ in[14] ^ in[15];
    out[13] = in[12] ^ gmul2[in[13]] ^ gmul3[in[14]] ^ in[15];
    out[14] = in[12] ^ in[13] ^ gmul2[in[14]] ^ gmul3[in[15]];
    out[15] = gmul3[in[12]] ^ in[13] ^ in[14] ^ gmul2[in[15]];
}

template <typename DataArrayIn1, typename DataArrayIn2, typename DataArrayOut>
static void state_xor(DataArrayIn1 const &in1, DataArrayIn2 const &in2, DataArrayOut &&out) {
    out[0] = in1[0] ^ in2[0]; out[1] = in1[1] ^ in2[1];
    out[2] = in1[2] ^ in2[2]; out[3] = in1[3] ^ in2[3];
    out[4] = in1[4] ^ in2[4]; out[5] = in1[5] ^ in2[5];
    out[6] = in1[6] ^ in2[6]; out[7] = in1[7] ^ in2[7];
    out[8] = in1[8] ^ in2[8]; out[9] = in1[9] ^ in2[9];
    out[10] = in1[10] ^ in2[10]; out[11] = in1[11] ^ in2[11];
    out[12] = in1[12] ^ in2[12]; out[13] = in1[13] ^ in2[13];
    out[14] = in1[14] ^ in2[14]; out[15] = in1[15] ^ in2[15];
}

template <typename DataArrayInOut, typename DataArrayIn>
static void state_xor_inplace(DataArrayInOut &&inout, DataArrayIn const &mask) {
    inout[0] ^= mask[0]; inout[1] ^= mask[1];
    inout[2] ^= mask[2]; inout[3] ^= mask[3];
    inout[4] ^= mask[4]; inout[5] ^= mask[5];
    inout[6] ^= mask[6]; inout[7] ^= mask[7];
    inout[8] ^= mask[8]; inout[9] ^= mask[9];
    inout[10] ^= mask[10]; inout[11] ^= mask[11];
    inout[12] ^= mask[12]; inout[13] ^= mask[13];
    inout[14] ^= mask[14]; inout[15] ^= mask[15];
}

////////////////////////////////////////////////////////////////////////
// AES round
template <int nround, int Round>
struct AESRound_impl
{
    template <typename State1, typename State2, typename ExpandedKey>
    static void encrypt(State1 &&out, State2 &&tmp, ExpandedKey const &expandedKey) {
        substitute(out, std::forward<State1>(out));
        shift_rows(out, std::forward<State2>(tmp));
        mix_columns(tmp, std::forward<State1>(out));
        state_xor_inplace(std::forward<State1>(out), std::begin(expandedKey) + 16*Round);
        AESRound_impl<nround, Round + 1>::encrypt(std::forward<State1>(out),
                                                    std::forward<State2>(tmp),
                                                    expandedKey);
    }
};

// last round
template <int nround>
struct AESRound_impl<nround, nround>
{
    template <typename State1, typename State2, typename ExpandedKey>
    static void encrypt(State1 &&out, State2 &&tmp, ExpandedKey const &expandedKey) {
        substitute(out, std::forward<State1>(out));
        shift_rows(out, std::forward<State2>(tmp));
        state_xor(tmp, expandedKey.data() + 16 *nround, std::forward<State1>(out));
    }
};

template <int nround>
struct AESRound
{
    template <typename State1, typename State2, typename ExpandedKey>
    static void encrypt(State1 &&out, State2 &&tmp, ExpandedKey const &expandedKey) {
        AESRound_impl<nround, 1>::encrypt(std::forward<State1>(out),
                                            std::forward<State2>(tmp), expandedKey);
    }
};

} // namespace internal

//////////////////////////////////////////////////////////////////
/////// AES     //////////////////////////////////////////////////

enum OperationMode { CTR_Mode, CBC_Mode };

template <int KeySize>
class AES : public internal::AES_traits<KeySize> {
public:
    static const int key_size = KeySize;
    static const int nround = internal::AES_traits<key_size>::nround;
    using typename internal::AES_traits<key_size>::Key;
    using typename internal::AES_traits<key_size>::RoundKey;
    using typename internal::AES_traits<key_size>::ExpandedKey;
    using typename internal::AES_traits<key_size>::State;

private:

private:
    Key key;
    ExpandedKey expandedKey;

public:
    template <typename KeyArray>
    AES(KeyArray &&_key) : key(_key)
    {
        internal::AES_key_expand<key_size>(key, expandedKey);
    }

private:

public:
    template <typename DataArrayIn, typename DataArrayOut>
    void encrypt_block(DataArrayIn const &in, DataArrayOut &&out) {
        State tmp;
        internal::state_xor(in, expandedKey.data(), std::forward<DataArrayOut>(out));
        internal::AESRound<nround>::encrypt(std::forward<DataArrayOut>(out), tmp, expandedKey);
    }

    template <typename DataArrayIn, typename DataArrayOut>
    void encrypt_array(DataArrayIn const &in, DataArrayOut &&out) {
        auto ii = std::begin(in), ii_end = std::end(in);
        auto oi = std::begin(out);
        for (; ii != ii_end; std::advance(ii, 16)) {

        }
    }
};


//////////////////////////////////////////////////////////////////////
////// Operation Mode

#define REF32(x) *((std::uint32_t*)&(x))
#define PREF32(x) ((std::uint32_t*)(x))
#define REF64(x) *((std::uint64_t*)&(x))
#define PREF64(x) ((std::uint64_t*)(x))

template <int KeySize>
class AES_CTRMode
{
    typedef internal::AES_traits_base::State State;
    typedef AES<KeySize> BlockCipher;
    typedef typename BlockCipher::Key Key;

    std::uint64_t nonce, counter;
    BlockCipher block_cipher;

    State extra;
    int extra_size;

public:
    AES_CTRMode(Key const &key, std::uint64_t nonce)
        : nonce(nonce), counter(0), block_cipher(key), extra_size(0)
    {}

    template <typename InputIter, typename OutputIter>
    OutputIter encrypt_append(InputIter first, InputIter last, OutputIter d_first) {
        return append(first, last, d_first);
    }

    template <typename InputIter, typename OutputIter>
    OutputIter decrypt_append(InputIter first, InputIter last, OutputIter d_first) {
        return append(first, last, d_first);
    }

    template <typename InputIter, typename OutputIter>
    OutputIter encrypt_finish(InputIter first, InputIter last, OutputIter d_first) {
        State noncecounter, mask;
        append(first, last, d_first);

        // TODO: big endian
        *PREF64(noncecounter.data()) = nonce;
        *PREF64(noncecounter.data()+8) = counter;

        // PKCS5 padding
        if (extra_size > 0) {
            std::fill(std::begin(extra) + extra_size, std::end(extra), 16 - extra_size);
        } else {
            extra.fill(16);
        }
        block_cipher.encrypt_block(noncecounter, mask);
        internal::state_xor(mask, extra, d_first);
        return d_first + 16;
    }

    template <typename InputIter, typename OutputIter>
    OutputIter decrypt_finish(InputIter first, InputIter last, OutputIter d_first) {
        auto di = decrypt_append(std::forward<InputIter>(first), std::forward<InputIter>(last),
                                 std::forward<OutputIter>(d_first));
        return di - *(di - 1);
    }


private:
    template <typename InputIter, typename OutputIter>
    OutputIter append(InputIter &&first, InputIter &&last, OutputIter &&d_first) {
//        std::uint64_t counter = 0;
        State noncecounter, mask;

        // TODO: big endian
        *PREF64(noncecounter.data()) = nonce;
        if (extra_size > 0) {
            auto remaining = std::min<int>(16 - extra_size, last - first);
            std::copy(first, first + remaining, std::begin(extra) + extra_size);
            first += remaining; extra_size += remaining;
            if (extra_size < 16)
                return d_first;

            // TODO: big endian
            *PREF64(noncecounter.data()+8) = counter++;
            block_cipher.encrypt_block(noncecounter, mask);
            internal::state_xor(mask, extra, d_first);

            d_first += 16;
        }

        encrypt_multiblock(first, last, d_first);

        extra_size = last - first;
        std::copy(first, last, std::begin(extra));
        return d_first;
    }

    template <typename InputIter, typename OutputIter>
    void encrypt_multiblock(InputIter &&first, InputIter &&last, OutputIter &&d_first) {
//        std::uint64_t counter = 0;
        State noncecounter, mask;

        // TODO: big endian
        *PREF64(noncecounter.data()) = nonce;
        auto num_blocks = (last - first) / 16;
#ifdef _OPENMP
#pragma omp parallel for firstprivate(noncecounter) private(mask)
#endif
        for (auto i = 0; i < num_blocks ; ++i) {
            // TODO: big endian
            *PREF64(noncecounter.data()+8) = counter + i;
            block_cipher.encrypt_block(noncecounter, mask);
            internal::state_xor(mask, first + i*16, d_first + i*16);
        }
        auto distance = num_blocks * 16;
        d_first += distance; first += distance;
        counter += num_blocks;
    }
};

} // namespace aes
#endif	/* AES_HPP */
