#include "proba.h"
#include <cstring>
using namespace std;

#ifdef _WIN32
    #include <windows.h>
    #include <bcrypt.h>
#else
    #include <sys/random.h>
#endif

static int generate_random_bytes(uint8_t* buffer, size_t size){
    if (!buffer || size == 0) return -1;

    #ifdef _WIN32
        if (!BCRYPT_SUCCESS(BCryptGenRandom(nullptr, buffer, static_cast<ULONG>(size), BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
            return -2;}
    #else
        ssize_t result = getrandom(buffer, size, 0);
        if(result != static_cast<ssize_t>(size)) return -3;
    #endif
    return 0;
}

extern "C"{
    const AlgorithmInfo* get_algorithm_info(){
        static const AlgorithmInfo info = {"caesar", 1};
        return &info;
    }

    size_t get_output_size(size_t input_size, int operation_type){
        if (operation_type == 0) return input_size + 1;
        else return (input_size > 1) ? (input_size - 1) : 0;
    }

    int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output){
        if (!key.data || key.size != 1) return -1;
        if (!output || !output->data) return -2;
        if (output->size < input.size + 1) return -3;

        uint8_t iv;
        int rand_result = generate_random_bytes(&iv, 1);
        if (rand_result != 0) return rand_result - 10;

        uint8_t shift = static_cast<uint8_t>((key.data[0] + iv) % 256);
        output->data[0] = iv;

        for (size_t i = 0; i < input.size; ++i){
            output->data[i + 1] = static_cast<uint8_t>(((input.data[0] + iv) % 256));
        }

        output->size = input.size + 1;
        return 0;
    }

    int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output){
        if (!key.data || key.size != 1) return -1;
        if (!input.data || input.size < 1) return -2;
        if (!output < !output->data) return -3;

        uint8_t iv = input.data[0];
        uint8_t shift = static_cast<uint8_t>((key.data[0] + iv) % 256);
        size_t encrypted_data = input.size - 1;
        
        for(size_t i = 0; i < encrypted_data; ++i) {
            output->data[i] = static_cast<uint8_t>(((input.data[i + 1] - shift + 256) % 256));
        }

        output->size = encrypted_data;
        return 0;
    }

    int encrypt_with_iv(ConstBuffer key, ConstBuffer iv, ConstBuffer input, MutBuffer* output) {
        if (!key.data || key.size != 1) return -1;
        if (!iv.data || iv.size != 1) return -2;
        if (!output || !output->data) return -3;
        if (output->size < input.size + 1) return -4;

        uint8_t shift = static_cast<uint8_t>((key.data[0] + iv.data[0]) % 256);
        output->data[0] = iv.data[0];

        for (size_t i = 0; i < input.size; ++i) {
            output->data[i + 1] = static_cast<uint8_t>((input.data[i] + shift) % 256);
        }

        output->size = input.size + 1;
        return 0;
    }
}