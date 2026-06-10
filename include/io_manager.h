#ifndef IOMANAGER_H
#define IOMANAGER_H
#include<vector>
#include <cstdint>
#include <string>

namespace io_manager{

    std::vector<uint8_t> read_binary_data(const std::string& path);
    void write_binary_data(const std::string& path, std::vector<uint8_t>& data);
}

#endif