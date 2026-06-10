#ifndef KEY_MANAGER_H
#define KEY_MANAGER_H
#include <vector>
#include <cstdint>

namespace key_manager {
std::vector<uint8_t> generate_secure_key(size_t key_size);
std::vector<uint8_t> read_key_from_file(const std::string& file_path);
std::vector<uint8_t> read_key_from_stdin();
}
#endif 