#pragma once
#include <cstdint>
#include <cstddef>

struct ConstBuffer {
    const uint8_t* data;
    size_t size;
};

struct MutBuffer {
    uint8_t* data;
    size_t size;
};

struct AlgorithmInfo {
    const char* algorithm_name;
    size_t key_size;
};

extern "C" const AlgorithmInfo* get_algorithm_info();
extern "C" size_t get_output_size(size_t input_size, int operation_type);
extern "C" int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output);
extern "C" int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output);
