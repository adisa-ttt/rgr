#include "crypto_interface.h"
using namespace std;

extern "C"{
    const AlgorithmInfo* get_algorithm_info(){
        static const AlgorithmInfo info = {"vigenere", 16};
        return &info;
    }

    size_t get_output_size(size_t input_size, int operation_type){
        (void)operation_type;
        return input_size;
    }

    int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output){
        if (!key.data || key.size != 16) return 1;
        if (!input.data && input.size > 0) return 2;
        if (!output || (input.size > 0 && !output->data)) return 3;
        if (output->size < input.size) return 4;

        for (size_t i = 0; i < input.size; ++i){
            output->data[i] = static_cast<uint8_t>((input.data[i] + key.data[i % 16]) % 256);
        }
        output->size = input.size;
        return 0;
    }

    int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output){
        if (!key.data || key.size != 16) return 1;
        if (!input.data && input.size > 0) return 2;
        if (!output || (input.size > 0 && !output->data)) return 3;
        if (output->size < input.size) return 4;

        for (size_t i = 0; i < input.size; ++i){
            output->data[i] = static_cast<uint8_t>((input.data[i] - key.data[i % 16] + 256) % 256);
        }
        output->size = input.size;
        return 0;
    }
}