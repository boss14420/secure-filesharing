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
#if defined(_WIN32) && defined(_MSC_VER)
#include <windows.h>
#pragma comment(lib, "advapi32.lib")
#endif
namespace util {
#if defined(_WIN32) && defined(_MSC_VER)
std::uint8_t *urandom(std::uint8_t *bytes, std::size_t len)
{
	HCRYPTPROV hProvider = 0;

	if (!::CryptAcquireContextW(&hProvider, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
		return nullptr;

	if (!::CryptGenRandom(hProvider, len, bytes))
	{
		::CryptReleaseContext(hProvider, 0);
		return nullptr;
	}
	
	if (!::CryptReleaseContext(hProvider, 0))
		return nullptr;
	return bytes;
}
#else
std::uint8_t *urandom(std::uint8_t *bytes, std::size_t len)
{
    FILE *f = std::fopen("/dev/urandom", "rb");
    std::fread(bytes, 1, len, f);
    std::fclose(f);

    return bytes;
}
#endif

} // namespace util
