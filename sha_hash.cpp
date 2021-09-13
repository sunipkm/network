/**
 * @file sha_hash.cpp
 * @author Sunip K. Mukherjee (sunipkmukherjee@gmail.com)
 * @brief Implementation of SHA512 based authentication token class
 * @version 1.0
 * @date 2021-09-13
 * 
 * @copyright Copyright (c) 2021
 * 
 */
#include "sha_hash.hpp"

void sha1_hash_t::clear()
{
    memset(bytes, 0, sizeof(bytes));
}

const uint8_t *sha1_hash_t::getBytes() const
{
    return bytes;
}

sha1_hash_t::sha1_hash_t()
{
    clear();
}
sha1_hash_t::sha1_hash_t(const char *pass, size_t len)
{
    if (pass != NULL && pass != nullptr)
    {
        SHA512_CTX ctx;
        SHA512_Init(&ctx);
        SHA512_Update(&ctx, pass, len);
        SHA512_Final(bytes, &ctx);
    }
}
void sha1_hash_t::copy(const sha1_hash_t &src)
{
    if ((src.getBytes() != nullptr) && (src.validate()))
        memcpy(bytes, src.getBytes(), sizeof(bytes));
}
const bool sha1_hash_t::validate() const
{
    int result = 0;
    for (int i = 0; i < sizeof(bytes); i++)
        result |= bytes[i];
    if (result == 0)
        return false;
    return true;
}
bool sha1_hash_t::operator==(const sha1_hash_t &hash) const
{
    bool match = true;
    for (int i = 0; i < sizeof(bytes); i++)
    {
        match = bytes[i] == hash.bytes[i];
        if (!match)
            break;
    }
    return match;
}
bool sha1_hash_t::operator!=(const sha1_hash_t &hash) const
{
    return !sha1_hash_t::operator==(hash);
}