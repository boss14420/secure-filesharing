/*
 * =====================================================================================
 *
 *       Filename:  primegen.hpp
 *
 *    Description:
 *
 *        Version:  1.0
 *        Created:  12/06/2014 01:29:04 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (),
 *   Organization:
 *
 * =====================================================================================
 */

#ifndef __PRIMEGEN_HPP__
#define __PRIMEGEN_HPP__

#include <iostream>
#include <random>
#include <bitset>
#include <cstdio>
#include <chrono>

#include "bigint.hpp"
#include "util.hpp"

namespace rsa {

static unsigned small_primes[] = {2,   3,   5,   7,  11,  13,  17,  19,  23,  29,  31,  37,  41, 43,  47,  53,  59,  61,  67,  71};
static unsigned small_primes2[] = {
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
    197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307,
    311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421,
    431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547,
    557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659,
    661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797,
    809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929,
    937, 941, 947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019, 1021, 1031, 1033, 1039,
    1049, 1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153,
    1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277, 1279,
    1283, 1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399, 1409,
    1423, 1427, 1429, 1433, 1439, 1447, 1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499,
    1511, 1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609, 1613,
    1619, 1621, 1627, 1637, 1657, 1663, 1667, 1669, 1693, 1697, 1699, 1709, 1721, 1723, 1733, 1741,
    1747, 1753, 1759, 1777, 1783, 1787, 1789, 1801, 1811, 1823, 1831, 1847, 1861, 1867, 1871, 1873,
    1877, 1879, 1889, 1901, 1907, 1913, 1931, 1933, 1949, 1951, 1973, 1979, 1987, 1993, 1997, 1999,
    2003, 2011, 2017, 2027, 2029, 2039, 2053, 2063, 2069, 2081, 2083, 2087, 2089, 2099, 2111, 2113,
    2129, 2131, 2137, 2141, 2143, 2153, 2161, 2179, 2203, 2207, 2213, 2221, 2237, 2239, 2243, 2251,
    2267, 2269, 2273, 2281, 2287, 2293, 2297, 2309, 2311, 2333, 2339, 2341, 2347, 2351, 2357, 2371,
    2377, 2381, 2383, 2389, 2393, 2399, 2411, 2417, 2423, 2437, 2441, 2447, 2459, 2467, 2473, 2477,
    2503, 2521, 2531, 2539, 2543, 2549, 2551, 2557, 2579, 2591, 2593, 2609, 2617, 2621, 2633, 2647,
    2657, 2659, 2663, 2671, 2677, 2683, 2687, 2689, 2693, 2699, 2707, 2711, 2713, 2719, 2729, 2731, 2741};

template <typename BigInt>
class primegen {

    static const int sieve_size = 5000;

    template<int SieveSize = sieve_size>
    static std::bitset<SieveSize> init_sieve(BigInt const &start)
    {
        std::bitset<SieveSize> sieve;
        for (auto &p : small_primes2) {
            unsigned long r = BigInt(start % p).get_ui();
            for (auto offset = p - r; offset < sieve_size; offset+=p)
                sieve[offset] = true;
        }
        return sieve;
    }

    // n - 1 = t * 2^s
    static bool rabin_miller_test(BigInt const &n, BigInt const &t, int s, BigInt &b)
    {
        b = bigint::powm(b, t, n);
//        mpz_powm(b.get_mpz_t(), b.get_mpz_t(), t.get_mpz_t(), n.get_mpz_t());
        if (b == 1 || b == n - 1) return true;

        for (int i = 0; i < s - 1; ++i) {
//            mpz_powm_ui(b.get_mpz_t(), b.get_mpz_t(), 2, n.get_mpz_t());
            b = bigint::powm_ui(b, 2, n);
            if (b == n - 1)
                return true;
        }
        return false;
    }

    static bool prime_test(BigInt const &n, int test_num=40) {
        // test with small primes
    ////    for (auto p : small_primes)
    //    for (auto pi = small_primes + 2; pi != small_primes + small_primes_len; ++pi)
    ////        if (n % p == 0)
    //        if (mpz_divisible_ui_p(n.get_mpz_t(), *pi))
    //            return false;

        // check whether n is Fermat pseudo-prime base 2
        BigInt tmp;
//        mpz_powm(tmp.get_mpz_t(), (2_mpz).get_mpz_t(),
//                BigInt((n - 1)).get_mpz_t(), n.get_mpz_t());
        tmp = bigint::powm<BigInt>(2, n - 1, n);
        if (tmp != 1) return false;

        // check whether n is strong pseudo-prime
        BigInt t = n - 1; int s = 0;
        while ((t.get_ui() & 1) == 0) {
            ++s; t>>=1;
        }

        for (auto p : small_primes) {
            auto pp = BigInt(p);
            if (!rabin_miller_test(n, t, s, pp))
                return false;
        }

        int i = sizeof(small_primes)/(sizeof(small_primes[0]));
        std::random_device rd;
        std::default_random_engine e1(rd());
        std::uniform_int_distribution<int>
            dist(small_primes[i-1] + 1, std::numeric_limits<int>::max());
        for (; i < test_num; ++i) {
            auto base = BigInt(dist(e1));
            if (!rabin_miller_test(n, t, s, base))
                return false;
        }

        return true;
    }

public:
    static BigInt random_prime(std::size_t size, int test_num=40)
    {
        std::vector<unsigned char> bytearray(size, 0);
        BigInt n;
        unsigned offset;
        while (true) {
//            std::fprintf(stderr, "\nGenerating random number ...\n");
            util::urandom(bytearray.data(), size);
            bytearray[0] |= 0x80; // MSB always 1
            bytearray[size - 1] |= 0x1; // LSB always 1
            n = bigint::bytes_to_int<BigInt>(&bytearray[0], size);
//            mpz_import(n.get_mpz_t(), size, 1, 1, 0, 0, &bytearray[0]);

//            auto start = std::chrono::high_resolution_clock::now();
    //        n = n/6*6 - 1;
    //        n -= n % prod_of_primes;
            auto sieve = init_sieve(n);
            unsigned max_step = (std::size_t)(size * 8 * std::log(2.)) * 2,// / 4,
                step = 0U;
    //        for (std::size_t step = 0; step < max_step; ++step) {
    //            std::fprintf(stderr, "Testing %lu ...\r", step);
    //            if (prime_test(n, test_num))
    //                return n;
    //            if (prime_test(n+2, test_num))
    //                return n + 2;
    //            n += 6;
    //        }
            for (offset = 0; offset < max_step; ++offset) {
                if (!sieve[offset]) {
//                    std::fprintf(stderr, "Testing %u / %u ...\r", step, offset);
                    ++step;
                    if (prime_test(n + offset, test_num))
                        break;
                }
            }
//            std::chrono::duration<double> elapsed = std::chrono::high_resolution_clock::now() - start;
//            std::fprintf(stderr, "\nAverage test time %fs\n", elapsed.count() / (step + 1));
            if (offset < max_step) break;
        }
        return n + offset;
    }

};

} // namespace rsa

#endif // __PRIMEGEN_HPP__
