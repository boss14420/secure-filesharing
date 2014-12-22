/*
 * =====================================================================================
 *
 *       Filename:  bigint.cc
 *
 *    Description:  template specialization of function templates in bigint.hpp
 *
 *        Version:  1.0
 *        Created:  12/21/2014 06:01:49 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (),
 *   Organization:
 *
 * =====================================================================================
 */

#include "include/config.hh"
#include "include/bigint.hpp"

namespace bigint {

/////////////////////////////////////////////////////////////////
////// powm
//
#ifdef USE_GMP
template <>
mpz_class powm<mpz_class>(mpz_class const &b, mpz_class const &p,
                            mpz_class const &m)
{
    mpz_class res;
    mpz_powm(res.get_mpz_t(), b.get_mpz_t(),
                p.get_mpz_t(), m.get_mpz_t());
    return res;
}

template <>
mpz_class powm_ui<mpz_class>(mpz_class const &b, unsigned long p,
                            mpz_class const &m)
{
    mpz_class res;
    mpz_powm_ui(res.get_mpz_t(), b.get_mpz_t(), p, m.get_mpz_t());
    return res;
}
#endif

/////////////////////////////////////////////////////////////////
////// divide_qr
//
#ifdef USE_GMP
template <>
void divide_qr<mpz_class>(mpz_class const &x, mpz_class const &y,
                               mpz_class &q, mpz_class &r)
{
    mpz_tdiv_qr(q.get_mpz_t(), r.get_mpz_t(), x.get_mpz_t(), y.get_mpz_t());
}
#endif

//////////////////////////////////////////////////////////////////
/////// sign
//
#ifdef USE_GMP
template <> int sign<mpz_class>(mpz_class const &bi) {
    return sgn(bi);
}
#endif

//////////////////////////////////////////////////////////////////
/////// bytes to int
//
#ifdef USE_GMP
template <>
mpz_class bytes_to_int<mpz_class>(byte const *bytes, std::size_t size)
{
    mpz_class n;
    mpz_import(n.get_mpz_t(), size, 1, 1, 1, 0, bytes);
    return n;
}

template <>
byte* int_to_bytes<mpz_class>(mpz_class const &n,
                                byte *bytes, std::size_t size)
{
    std::size_t count;
    mpz_export(bytes, &count, 1, 1, 1, 0, n.get_mpz_t());
    if (count < size) {
        std::copy_backward(bytes, bytes + count, bytes + size);
        std::fill_n(bytes, size - count, 0);
    }
    return bytes;
}
#endif

} // namespace bigint
