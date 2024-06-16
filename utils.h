#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <cstdint>

// Shared constants between the client and the server
const std::string NAME_FILE_PUBLIC_KEY = "cloud.key";
const std::string NAME_FILE_WITH_CIPHER_BANNED_IPS = "banned_ip.data";
const std::string NAME_FILE_WITH_CIPHER_NETWORK_FLOW = "ip_to_analyze.data";
const std::string NAME_FILE_WITH_RESULT_OF_ANALYZE = "answer.data";

/**
 * @brief Get the remaining bits in a file
 */
long get_remaining_bits(FILE* file);

/**
 * @brief Print a uint32_t in binary format
 */
void printBinary(uint32_t num);

#endif // UTILS_H