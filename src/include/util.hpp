/*
 * =====================================================================================
 *
 *       Filename:  util.hpp
 *
 *    Description:
 *
 *        Version:  1.0
 *        Created:  12/21/2014 01:14:44 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (),
 *   Organization:
 *
 * =====================================================================================
 */

#ifndef __UTIL_HPP__
#define __UTIL_HPP__

#include <cstdio>
#include <cstddef>
#include <cstdint>

namespace util {

std::uint8_t *urandom(std::uint8_t *bytes, std::size_t len);

}
#endif // __UTIL_HPP__
