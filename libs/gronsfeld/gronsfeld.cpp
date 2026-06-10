#include "../include/crypto_interface.h"
#include <cctype>

extern "C" {

const AlgorithmInfo* get_algorithm_info() {
    static AlgorithmInfo info = {"Gronsfeld", 0};
    return &info;
}

size_t get_output_size(size_t input_size, int operation_type) {
    (void)operation_type;
    return input_size;
}

static int validate_key(const uint8_t* data, size_t size) {
    if (size == 0) return 0;
    for (size_t i = 0; i < size; i++)
        if (!isdigit((unsigned char)data[i])) return 0;
    return (int)size;
}

int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (!output || output->size < input.size) return 1;
    int key_len = validate_key(key.data, key.size);
    if (key_len == 0) return 2;

    for (size_t i = 0; i < input.size; i++) {
        int shift = key.data[i % key_len] - '0';
        output->data[i] = (uint8_t)((input.data[i] + shift) % 256);
    }
    return 0;
}

int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (!output || output->size < input.size) return 1;
    int key_len = validate_key(key.data, key.size);
    if (key_len == 0) return 2;

    for (size_t i = 0; i < input.size; i++) {
        int shift = key.data[i % key_len] - '0';
        output->data[i] = (uint8_t)((input.data[i] - shift + 256) % 256);
    }
    return 0;
}

int encrypt_with_iv(ConstBuffer key, ConstBuffer iv, ConstBuffer input, MutBuffer* output) {
    (void)iv;
    return encrypt(key, input, output);
}

}
