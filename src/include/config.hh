/*
 * =====================================================================================
 *
 *       Filename:  config.hh
 *
 *    Description:
 *
 *        Version:  1.0
 *        Created:  12/21/2014 03:59:40 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (),
 *   Organization:
 *
 * =====================================================================================
 */

#ifndef __CONFIG_HH__
#define __CONFIG_HH__

#define USE_GMP
#ifdef _WIN32
#include <mpirxx.h>
#else
#include <gmpxx.h>
#endif
typedef mpz_class BigInt;

#endif // __CONFIG_HH__
