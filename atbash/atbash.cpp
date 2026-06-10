#include "atbash.h"

extern "C" const AlgorithmInfo* get_algorithm_info(){
    static AlgorithmInfo info = {
        "atbash",
        0
    };
    return &info;
}

extern "C" size_t get_output_size(size_t input_size, int operation_type){
    return input_size;
}

extern "C" int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output){
    MutBuffer& out = *output;
    if (out.size < input.size) return 1;
    for (size_t i = 0; i < input.size; ++i){
        out.data[i] = 255 - input.data[i];
    }
    return 0;
}

extern "C" int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output){
    return encrypt(key, input, output);
}