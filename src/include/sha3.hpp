#include <iostream>
#include <array>
#include <limits>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <emmintrin.h>

using std::uint64_t;

template <int HashSize>
class SHA3
{
    static_assert(HashSize == 224 || HashSize == 256 || HashSize == 384 || HashSize == 512,
                    "HashSize must be 224, 256, 384, 512");
public:
    static const int nr = 24;
    typedef uint64_t Lane;
    typedef unsigned char byte;
    typedef Lane State[25];

    static const int b = 1600;
    static const int w = b / 25;
    static const Lane mask = std::numeric_limits<Lane>::max();

    static const int d = HashSize, dd = d / 8;
    static const int c = HashSize * 2, cc = c / 8;
    static const int r = b - c, rr = r / 8;
    static const Lane rc[];

    #define HEX_DUMP(s, l) for (int i = 0; i != l; ++i) { \
                                    std::printf("%02X", *(reinterpret_cast<unsigned char const*>(s) + i)); \
                                } std::putchar('\n')

    alignas(16) State state;
    alignas(16) char extra[rr];
    alignas(16) mutable State _final_state;
    std::size_t extra_bytes;
    mutable bool _updated = false;

public:
    SHA3(char const *message = nullptr, std::size_t len = 0) {
        reset(message, len);
    }

    char *digest(char *dst) const
    {
        if (!_updated) {
            calculate_digest();
            _updated = true;
        }
        std::memcpy(dst, _final_state, dd);
        return dst;
    }

    char *hex_digest(char *dst) const
    {
        if (!_updated) {
            calculate_digest();
            _updated = true;
        }
        char const *ps = reinterpret_cast<char const*>(_final_state);
        for (int i = 0; i != dd; ++i) {
            std::sprintf(dst + i*2, "%02X", (unsigned char)ps[i]);
        }
        dst[dd * 2] = '\0';
        return dst;
    }

    SHA3& append(char const *message, std::size_t len)
    {
        // append to extra
        std::size_t nbytes_pad = (rr - extra_bytes) % rr;
        nbytes_pad = std::min(nbytes_pad, len);
        std::memcpy(extra + extra_bytes, message, nbytes_pad);
        extra_bytes += nbytes_pad;
//        std::cout << len << ", " << nbytes_pad << ", " << extra_bytes << '\n';

        if (extra_bytes == rr) {
            absorb_part(extra, state);
            absorb(message + nbytes_pad, len - nbytes_pad);
        } else if(extra_bytes == 0) {
            absorb(message, len);
        }

//        std::cout << extra_bytes << '\n';
        _updated = false;
        return *this;
    }

    SHA3& reset(char const *message = nullptr, std::size_t len = 0)
    {
        std::memset(state, 0, 8*25);
        absorb(message, len);
        _updated = false;
        return *this;
    }

private:
    static void absorb_part(char const *message, State &state)
    {
        // state = state XOR (message + '0' * cc)
        Lane *ps = state;
        char const *pm = message;
        for (; pm < message + rr; pm += 8, ++ps) {
            // TODO: big-endian systems?
            *ps ^= *reinterpret_cast<Lane const*>(pm);
        }
        char *pcs = reinterpret_cast<char *>(ps);
        for (; pm < message + rr; ++pm, ++pcs)
            *pcs ^= *pm;

        // keccak
        keccak_p(state);
    }

    void absorb(char const *message, std::size_t len)
    {
        std::size_t n = len / rr;
        extra_bytes = len % rr;
        std::memcpy(extra, message + n * rr, extra_bytes);

        for (std::size_t i = 0; i != n; ++i) {
            // absorb
            absorb_part(message + rr * i, state);
        }
    }

    void calculate_digest() const
    {
        // pad
        alignas(16) byte last_part[rr];
        std::memcpy((char*)last_part, extra, extra_bytes);
        std::size_t nbytes_pad = rr - (extra_bytes % rr);

        // TODO: generic padding (for SHAKE*)
        if (nbytes_pad > 1) {
            last_part[extra_bytes] = 0x06;
            std::memset((char*)last_part + extra_bytes + 1, 0, nbytes_pad-2);
            last_part[rr - 1] = 0x80;
        } else last_part[rr - 1] = 0x86;

        std::memcpy(_final_state, reinterpret_cast<char const*>(state), sizeof(state));

        // absorb last part
        absorb_part((char*)last_part, _final_state);

//        // result
//        std::memcpy(_final_state, reinterpret_cast<char const*>(state), dd);
    }

    static Lane rot1(Lane x) {
        return ((x << 1) | (x >> (w - 1))) & mask;
    }

    static void rot(Lane &x, int b) {
        x = ((x << b) | (x >> (w - b))) & mask;
    }

    static void keccak_p(State &s)
    {
        alignas(16) State t;
        alignas(16) Lane c[5], d[5];
        Lane *ps, *pt;
//        __m128i d01, d23, d4;
//        __m128i s01, s23, s56, s78;
        for (int ir = 0; ir != nr; ++ir) {
            // theta
            c[0] = s[0] ^ s[5] ^ s[10] ^ s[15] ^ s[20];
            c[1] = s[1] ^ s[6] ^ s[11] ^ s[16] ^ s[21];
            c[2] = s[2] ^ s[7] ^ s[12] ^ s[17] ^ s[22];
            c[3] = s[3] ^ s[8] ^ s[13] ^ s[18] ^ s[23];
            c[4] = s[4] ^ s[9] ^ s[14] ^ s[19] ^ s[24];

            d[0] = c[4] ^ rot1(c[1]);
            d[1] = c[0] ^ rot1(c[2]);
            d[2] = c[1] ^ rot1(c[3]);
            d[3] = c[2] ^ rot1(c[4]);
            d[4] = c[3] ^ rot1(c[0]);

//            for (int i = 0; i != 25; ++i)
//                s[i] ^= d[i % 5];
//            s[0] ^= d[0]; s[1] ^= d[1]; s[2] ^= d[2]; s[3] ^= d[3]; s[4] ^= d[4];
//            s[5] ^= d[0]; s[6] ^= d[1]; s[7] ^= d[2]; s[8] ^= d[3]; s[9] ^= d[4];
//            s[10] ^= d[0]; s[11] ^= d[1]; s[12] ^= d[2]; s[13] ^= d[3]; s[14] ^= d[4];
//            s[15] ^= d[0]; s[16] ^= d[1]; s[17] ^= d[2]; s[18] ^= d[3]; s[19] ^= d[4];
//            s[20] ^= d[0]; s[21] ^= d[1]; s[22] ^= d[2]; s[23] ^= d[3]; s[24] ^= d[4];

            ps = s-1;
            *++ps ^= d[0]; *++ps ^= d[1]; *++ps ^= d[2]; *++ps ^= d[3]; *++ps ^= d[4];
            *++ps ^= d[0]; *++ps ^= d[1]; *++ps ^= d[2]; *++ps ^= d[3]; *++ps ^= d[4];
            *++ps ^= d[0]; *++ps ^= d[1]; *++ps ^= d[2]; *++ps ^= d[3]; *++ps ^= d[4];
            *++ps ^= d[0]; *++ps ^= d[1]; *++ps ^= d[2]; *++ps ^= d[3]; *++ps ^= d[4];
            *++ps ^= d[0]; *++ps ^= d[1]; *++ps ^= d[2]; *++ps ^= d[3]; *++ps ^= d[4];

            // rho
//            rot(s[1], 1); rot(s[2], 62); rot(s[3], 28); rot(s[4], 27);
//            rot(s[5], 36); rot(s[6], 44); rot(s[7], 6); rot(s[8], 55); rot(s[9], 20);
//            rot(s[10], 3); rot(s[11], 10); rot(s[12], 43); rot(s[13], 25); rot(s[14], 39);
//            rot(s[15], 41); rot(s[16], 45); rot(s[17], 15); rot(s[18], 21); rot(s[19], 8);
//            rot(s[20], 18); rot(s[21], 2); rot(s[22], 61); rot(s[23], 56); rot(s[24], 14);

            ps = s;
            rot(*++ps, 1); rot(*++ps, 62); rot(*++ps, 28); rot(*++ps, 27);
            rot(*++ps, 36); rot(*++ps, 44); rot(*++ps, 6); rot(*++ps, 55); rot(*++ps, 20);
            rot(*++ps, 3); rot(*++ps, 10); rot(*++ps, 43); rot(*++ps, 25); rot(*++ps, 39);
            rot(*++ps, 41); rot(*++ps, 45); rot(*++ps, 15); rot(*++ps, 21); rot(*++ps, 8);
            rot(*++ps, 18); rot(*++ps, 2); rot(*++ps, 61); rot(*++ps, 56); rot(*++ps, 14);

            // pi
//            t[0] = s[0]; t[1] = s[6]; t[2] = s[12]; t[3] = s[18]; t[4] = s[24];
//            t[5] = s[3]; t[6] = s[9]; t[7] = s[10]; t[8] = s[16]; t[9] = s[22];
//            t[10] = s[1]; t[11] = s[7]; t[12] = s[13]; t[13] = s[19]; t[14] = s[20];
//            t[15] = s[4]; t[16] = s[5]; t[17] = s[11]; t[18] = s[17]; t[19] = s[23];
//            t[20] = s[2]; t[21] = s[8]; t[22] = s[14]; t[23] = s[15]; t[24] = s[21];

            pt = t-1;
            *++pt = s[0]; *++pt = s[6]; *++pt = s[12]; *++pt = s[18]; *++pt = s[24];
            *++pt = s[3]; *++pt = s[9]; *++pt = s[10]; *++pt = s[16]; *++pt = s[22];
            *++pt = s[1]; *++pt = s[7]; *++pt = s[13]; *++pt = s[19]; *++pt = s[20];
            *++pt = s[4]; *++pt = s[5]; *++pt = s[11]; *++pt = s[17]; *++pt = s[23];
            *++pt = s[2]; *++pt = s[8]; *++pt = s[14]; *++pt = s[15]; *++pt = s[21];

            // chi
//            s[0] = t[0] ^ (~t[1] & t[2]); s[1] = t[1] ^ (~t[2] & t[3]); s[2] = t[2] ^ (~t[3] & t[4]);
//            s[3] = t[3] ^ (~t[4] & t[0]); s[4] = t[4] ^ (~t[0] & t[1]);
//            s[5] = t[5] ^ (~t[6] & t[7]); s[6] = t[6] ^ (~t[7] & t[8]); s[7] = t[7] ^ (~t[8] & t[9]);
//            s[8] = t[8] ^ (~t[9] & t[5]); s[9] = t[9] ^ (~t[5] & t[6]);
//            s[10] = t[10] ^ (~t[11] & t[12]); s[11] = t[11] ^ (~t[12] & t[13]); s[12] = t[12] ^ (~t[13] & t[14]);
//            s[13] = t[13] ^ (~t[14] & t[10]); s[14] = t[14] ^ (~t[10] & t[11]);
//            s[15] = t[15] ^ (~t[16] & t[17]); s[16] = t[16] ^ (~t[17] & t[18]); s[17] = t[17] ^ (~t[18] & t[19]);
//            s[18] = t[18] ^ (~t[19] & t[15]); s[19] = t[19] ^ (~t[15] & t[16]);
//            s[20] = t[20] ^ (~t[21] & t[22]); s[21] = t[21] ^ (~t[22] & t[23]); s[22] = t[22] ^ (~t[23] & t[24]);
//            s[23] = t[23] ^ (~t[24] & t[20]); s[24] = t[24] ^ (~t[20] & t[21]);

            ps = s - 1;
            *++ps = t[0] ^ (~t[1] & t[2]); *++ps = t[1] ^ (~t[2] & t[3]); *++ps = t[2] ^ (~t[3] & t[4]);
            *++ps = t[3] ^ (~t[4] & t[0]); *++ps = t[4] ^ (~t[0] & t[1]);
            *++ps = t[5] ^ (~t[6] & t[7]); *++ps = t[6] ^ (~t[7] & t[8]); *++ps = t[7] ^ (~t[8] & t[9]);
            *++ps = t[8] ^ (~t[9] & t[5]); *++ps = t[9] ^ (~t[5] & t[6]);
            *++ps = t[10] ^ (~t[11] & t[12]); *++ps = t[11] ^ (~t[12] & t[13]); *++ps = t[12] ^ (~t[13] & t[14]);
            *++ps = t[13] ^ (~t[14] & t[10]); *++ps = t[14] ^ (~t[10] & t[11]);
            *++ps = t[15] ^ (~t[16] & t[17]); *++ps = t[16] ^ (~t[17] & t[18]); *++ps = t[17] ^ (~t[18] & t[19]);
            *++ps = t[18] ^ (~t[19] & t[15]); *++ps = t[19] ^ (~t[15] & t[16]);
            *++ps = t[20] ^ (~t[21] & t[22]); *++ps = t[21] ^ (~t[22] & t[23]); *++ps = t[22] ^ (~t[23] & t[24]);
            *++ps = t[23] ^ (~t[24] & t[20]); *++ps = t[24] ^ (~t[20] & t[21]);

            // iota
            s[0] ^= rc[ir];
        }
    }

    #undef PAD_OF
    #undef HEX_DUMP
};

template <int HashSize>
const typename SHA3<HashSize>::Lane SHA3<HashSize>::rc[] = {
        0x0000000000000001, 0x0000000000008082,
        0x800000000000808A, 0x8000000080008000,
        0x000000000000808B, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009,
        0x000000000000008A, 0x0000000000000088,
        0x0000000080008009, 0x000000008000000A,
        0x000000008000808B, 0x800000000000008B,
        0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080,
        0x000000000000800A, 0x800000008000000A,
        0x8000000080008081, 0x8000000000008080,
        0x0000000080000001, 0x8000000080008008
};
