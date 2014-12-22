/*
 * =====================================================================================
 *
 *       Filename:  util.cc
 *
 *    Description:
 *
 *        Version:  1.0
 *        Created:  12/21/2014 06:09:38 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (),
 *   Organization:
 *
 * =====================================================================================
 */

#include "include/util.hpp"

namespace util {

std::uint8_t *urandom(std::uint8_t *bytes, std::size_t len)
{
    FILE *f = std::fopen("/dev/urandom", "rb");
    std::fread(bytes, 1, len, f);
    std::fclose(f);

    return bytes;
}

} // namespace util
