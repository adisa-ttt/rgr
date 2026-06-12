#include "../include/crypto_interface.h"
#include <cstdlib>
#include <cstring>
#include <vector>

extern "C" {

const AlgorithmInfo* get_algorithm_info() {
    static AlgorithmInfo info = {"Scytale", 1};
    return &info;
}

size_t get_output_size(size_t input_size, int operation_type) {
    (void)operation_type;
    return input_size + 16;
}

static int parseKey(ConstBuffer key) {
    if (key.size == 0) return -1;
    size_t len = key.size;
    while (len > 0) {
        unsigned char c = key.data[len - 1];
        if (c == ' ' || c == '\n' || c == '\r' || c == '\t') len--;
        else break;
    }
    if (len == 0) return -1;
    for (size_t i = 0; i < len; i++) {
        if (key.data[i] < '0' || key.data[i] > '9') return -1;
    }
    int m = 0;
    for (size_t i = 0; i < len; i++) m = m * 10 + (key.data[i] - '0');
    return (m > 1) ? m : -1;
}

static size_t get_utf8_char_len(uint8_t c) {
    if ((c & 0x80) == 0x00) return 1;       // 0xxxxxxx
    if ((c & 0xE0) == 0xC0) return 2;       // 110xxxxx
    if ((c & 0xF0) == 0xE0) return 3;       // 1110xxxx
    if ((c & 0xF8) == 0xF0) return 4;       // 11110xxx
    return 1; // По умолчанию считаем 1 байтом
}

int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (!output) return 1;
    int m = parseKey(key);
    if (m < 0) return 2;

    std::vector<std::vector<uint8_t>> chars;
    size_t i = 0;
    while (i < input.size) {
        size_t len = get_utf8_char_len(input.data[i]);
        std::vector<uint8_t> ch;
        for (size_t j = 0; j < len && (i + j) < input.size; ++j) {
            ch.push_back(input.data[i + j]);
        }
        chars.push_back(ch);
        i += len;
    }
    size_t padded_chars_count = chars.size();
    if (padded_chars_count % (size_t)m != 0) {
        padded_chars_count += (size_t)m - (padded_chars_count % (size_t)m);
    }
    while (chars.size() < padded_chars_count) {
        chars.push_back(std::vector<uint8_t>{' '});
    }

    size_t total_bytes = 0;
    for (const auto& ch : chars) total_bytes += ch.size();

    if (output->size < total_bytes) return 3;

    size_t rows = padded_chars_count / (size_t)m;
    size_t out_idx = 0;
    for (int col = 0; col < m; col++) {
        for (size_t row = 0; row < rows; row++) {
            size_t char_idx = row * (size_t)m + col;
            for (uint8_t b : chars[char_idx]) {
                output->data[out_idx++] = b;
            }
        }
    }

    output->size = total_bytes;
    return 0;
}

int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (!output) return 1;
    int m = parseKey(key);
    if (m < 0) return 2;

    std::vector<std::vector<uint8_t>> chars;
    size_t i = 0;
    while (i < input.size) {
        size_t len = get_utf8_char_len(input.data[i]);
        std::vector<uint8_t> ch;
        for (size_t j = 0; j < len && (i + j) < input.size; ++j) {
            ch.push_back(input.data[i + j]);
        }
        chars.push_back(ch);
        i += len;
    }

    size_t padded_chars_count = chars.size();
    if (padded_chars_count % (size_t)m != 0) {
        padded_chars_count += (size_t)m - (padded_chars_count % (size_t)m);
    }
    while (chars.size() < padded_chars_count) {
        chars.push_back(std::vector<uint8_t>{' '});
    }

    size_t total_bytes = 0;
    for (const auto& ch : chars) total_bytes += ch.size();

    if (output->size < total_bytes) return 3;

    size_t rows = padded_chars_count / (size_t)m;
    size_t out_idx = 0;
    for (size_t row = 0; row < rows; row++) {
        for (int col = 0; col < m; col++) {
            size_t char_idx = col * rows + row;
            for (uint8_t b : chars[char_idx]) {
                output->data[out_idx++] = b;
            }
        }
    }

    output->size = total_bytes;

    while (output->size > 0 && output->data[output->size - 1] == ' ') {
        output->size--;
    }

    return 0;
}

int encrypt_with_iv(ConstBuffer key, ConstBuffer iv, ConstBuffer input, MutBuffer* output) {
    (void)iv;
    return encrypt(key, input, output);
}

}
