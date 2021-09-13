/**
 * @file sha_hash.hpp
 * @author Sunip K. Mukherjee (sunipkmukherjee@gmail.com)
 * @brief SHA512 Hash based Authentication Token Generator
 * @version 1.0
 * @date 2021-09-13
 * 
 * @copyright Copyright (c) 2021
 * 
 */

#ifndef SHA1_HASH_HPP
#define SHA1_HASH_HPP
#include <openssl/sha.h>
#include <string.h>

class sha1_hash_t
{
private:
    /**
     * @brief Clear the contents
     * 
     */
    void clear();
    uint8_t bytes[SHA512_DIGEST_LENGTH];

public:
    /**
     * @brief Construct a new empty sha1_hash_t object
     * 
     */
    sha1_hash_t();
    /**
     * @brief Construct a new sha1_hash_t object that calculates the hash of the input password
     * 
     * @param pass Pointer to password
     * @param len Length of password
     */
    sha1_hash_t(const char *pass, size_t len);
    /**
     * @brief Get the pointer to the SHA512 digest of the password
     * 
     * @return const uint8_t* 
     */
    const uint8_t *getBytes() const;
    /**
     * @brief Copy the password data of a valid sha1_hash_t object into this object
     * 
     * @param src Source sha1_hash_t object
     */
    void copy(const sha1_hash_t &src);
    /**
     * @brief Validate a sha1_hash_t object token
     * 
     * @return true 
     * @return false 
     */
    const bool validate() const;
    bool operator==(const sha1_hash_t &) const;
    bool operator!=(const sha1_hash_t &) const;
};
#endif // SHA1_HASH_HPP