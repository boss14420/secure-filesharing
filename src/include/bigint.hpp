/*
 * =====================================================================================
 *
 *       Filename:  bigint.hpp
 *
 *    Description:
 *
 *        Version:  1.0
 *        Created:  12/20/2014 04:29:45 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (),
 *   Organization:
 *
 * =====================================================================================
 */

#ifndef __BIGINT_HPP__
#define __BIGINT_HPP__

#include <utility>
#include <cstdint>
#include <algorithm>

#include "config.hh"

#ifdef USE_BOOST_MP
    #include <boost/multiprecision/integer.hpp>
#endif

#ifdef USE_GMP
    #include <gmp.h>
#endif

namespace bigint {

#ifdef USE_BOOST_MP
namespace mp = boost::multiprecision;
#endif

/////////////////////////////////////////////////////////////////
////// powm
//
template <typename BigInt>
BigInt powm(BigInt const &b, BigInt const &p, BigInt const &m);

template <typename BigInt>
BigInt powm_ui(BigInt const &b, unsigned long p, BigInt const &m);

#ifdef USE_BOOST_MP
template <typename BigInt>
BigInt powm(BigInt const &b, BigInt const &p, BigInt const &m) {
    return mp::powm(b, p, m);
}
#endif

/////////////////////////////////////////////////////////////////
////// divide_qr
//
template <typename BigInt>
void divide_qr(BigInt const &x, BigInt const &y, BigInt &q, BigInt &r);

#ifdef USE_BOOST_MP
template <typename BigInt>
void divide_qr(BigInt const &x, BigInt const &y, BigInt &q, BigInt &r) {
    mp::divide_qr(x, y, q, r);
}
#endif

//////////////////////////////////////////////////////////////////
/////// sign
//
template <typename BigInt> int sign(BigInt const &bi);

#ifdef USE_BOOST_MP
template <typename BigInt> int sign(BigInt const &bi) {
    return bi.sign();
}
#endif

//////////////////////////////////////////////////////////////////
/////// invmod
//
template<typename BigInt>
BigInt invmod(BigInt const &a, BigInt const &m)
{
    BigInt s1 = 0, s0 = 1;
    BigInt r1 = m, r0 = a;
    BigInt q, r;
    while (sign(r1) != 0) {
        divide_qr(r0, r1, q, r);
        r0 = std::move(r1);
        r1 = std::move(r);

        r = s1;
        s1 = s0 - q * r;
        s0 = std::move(r);
    }
    while (sign(s0) < 0) s0 += m;
    return s0;
}


//////////////////////////////////////////////////////////////////
/////// bytes to int
//
typedef std::uint8_t byte;
template <typename BigInt>
BigInt bytes_to_int(byte const *bytes, std::size_t size);

template <typename BigInt>
byte* int_to_bytes(BigInt const &n, byte *bytes, std::size_t size);

template <typename BigInt, typename InputIter>
struct _bytes_to_int_helper;

} // namespace bigint
#endif // __BIGINT_HPP__
