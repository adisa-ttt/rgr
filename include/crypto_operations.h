#ifndef CRYPTOOPERATIONS_H
#define CRYPTOOPERATIONS_H
#include <vector>
#include <cstdint>

namespace crypto_operations {
    std::vector<uint8_t> encrypt(void* handle, const std::vector<uint8_t>& key, const std::vector<uint8_t>& input);
    std::vector<uint8_t> decrypt(void* handle, const std::vector<uint8_t>& key, const std::vector<uint8_t>& input);
}

#endif