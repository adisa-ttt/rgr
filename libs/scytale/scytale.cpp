#include "../include/cryptoInterface.h"
#include <cstdlib>

extern "C" {

const AlgorithmInfo* get_algorithm_info() {
    static AlgorithmInfo info = {"Scytale", 1};
    return &info;
}

size_t get_output_size(size_t input_size, int operation_type) {
    (void)operation_type;
    return input_size;
}

static int parseKey(ConstBuffer key) {
    if (key.size == 0) return -1;
    for (size_t i = 0; i < key.size; i++) {
        unsigned char c = key.data[i];
        if (c < '0' || c > '9') return -1;
    }
    int m = atoi((const char*)key.data);
    return (m > 1) ? m : -1;
}

int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (!output || output->size < input.size) return 1;
    int m = parseKey(key);
    if (m < 0) return 2;
    if (input.size % (size_t)m != 0) return 3;

    size_t rows = input.size / (size_t)m;
    size_t idx = 0;
    for (int col = 0; col < m; col++) {
        for (size_t row = 0; row < rows; row++) {
            output->data[idx++] = input.data[row * (size_t)m + col];
        }
    }
    return 0;
}

int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (!output || output->size < input.size) return 1;
    int m = parseKey(key);
    if (m < 0) return 2;
    if (input.size % (size_t)m != 0) return 3;

    size_t rows = input.size / (size_t)m;
    size_t idx = 0;
    for (int col = 0; col < m; col++) {
        for (size_t row = 0; row < rows; row++) {
            output->data[row * (size_t)m + col] = input.data[idx++];
        }
    }
    return 0;
}

int encrypt_with_iv(ConstBuffer key, ConstBuffer iv, ConstBuffer input, MutBuffer* output) {
    (void)iv;
    return encrypt(key, input, output);
}

}
