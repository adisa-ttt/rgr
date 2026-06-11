#include "crypto_interface.h"
#include <random>

static void clear_buffer(void* ptr, size_t size) {
    volatile uint8_t* p = reinterpret_cast<volatile uint8_t*>(ptr);
    while (size--) {
        *p++ = 0;
    }
}

static bool is_prime(uint64_t n){
    if (n < 2) return false;
    for (uint64_t i = 2; i * i <= n; ++i){
        if (n % i == 0) return false;
    }
    return true;
}

static uint64_t nod (uint64_t a, uint64_t b){
    while (b != 0){
        uint64_t t = b;
        b = a % b;
        a = t;
    }
    return a;
}

static uint64_t evklid_inverse (uint64_t e, uint64_t phi){
    int64_t m0 = phi, q, t;
    int64_t u = 1,  v = 0;
    while (e > 1){
        if (phi == 0) return 0;
        q = e / phi;
        t = phi;
        phi = e % phi;
        e = t;
        t = v;
        v = u - q*v;
        u = t;
    }
    if (u < 0) u += m0;
    return (uint64_t)u;
}

static uint64_t mul_mod(uint64_t a, uint64_t b, uint64_t mod) {
    uint64_t result = 0;
    a %= mod;
    while (b > 0) {
        if (b & 1) {
            result = (result + a) % mod;
        }
        a = (a + a) % mod;
        b >>= 1;
    }
    return result;
}


static uint64_t power_modulo (uint64_t base, uint64_t power, uint64_t mod){
    uint64_t result = 1;
    base %= mod;
    while (power > 0){
        if (power % 2 == 1){
            result = mul_mod(result, base, mod);
        }
        base = mul_mod(base, base, mod);
        power /= 2;
    }
    return result;
}

static uint64_t bytes_to_u64(const uint8_t* data) {
    uint64_t result = 0;
    for (int i = 0; i < 8; ++i) {
        result = (result << 8) | data[i];
    }
    return result;
}

static void u64_to_bytes(uint8_t* data, uint64_t value) {
    for (int i = 7; i >= 0; --i) {
        data[i] = (uint8_t)(value & 0xFF);
        value >>= 8;
    }
}

extern "C" const AlgorithmInfo* get_algorithm_info(){
    static AlgorithmInfo info ={"RSA-64",32};
    return &info;
}

extern "C" size_t get_output_size(size_t input_size, int operation_type){
    if (operation_type == 1){
        return ((input_size/8) + 1) * 8;
    }
    return input_size;
}

extern "C" int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output){
    if (!key.data || !input.data || !output) return 1;

    MutBuffer& out = *output;
    if (!out.data) return 1;

    size_t need_size = get_output_size (input.size, 0);
    if (out.size < need_size || key.size < 32) return 1;

    uint64_t n = bytes_to_u64 (key.data);
    uint64_t e = bytes_to_u64 (key.data + 8);
    if (n == 0 || e ==0) return 2;

    size_t blocks = need_size / 8;
    size_t pad_len = need_size - input.size;

    for (size_t i = 0; i < blocks; ++i){
        uint8_t block[8] = {0};
        for (size_t j = 0; j < 8; ++j){
            size_t idx = i * 8 + j;
            if (idx < input.size){
                block[j] = input.data[idx];
            }
            else {
                block[j] = (uint8_t)pad_len;
            }
        }
        uint64_t m = bytes_to_u64(block);
        uint64_t c = power_modulo(m, e, n);
        u64_to_bytes (out.data + i * 8, c);

        clear_buffer(block, 8);
    }
    clear_buffer(&n, sizeof(n));
    clear_buffer(&e, sizeof(e));

    out.size = need_size;
    return 0;
}

extern "C" int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output){
    if (!key.data || !input.data || !output) return 1;

    MutBuffer& out = *output;
    if (!out.data) return 1;

    if (input.size % 8 != 0 || key.size < 32) return 1;
    if (out.size < input.size) return 2;

    uint64_t n = bytes_to_u64(key.data + 16);
    uint64_t d = bytes_to_u64(key.data + 24);
    if (n == 0 || d == 0) return 3;

    size_t blocks = input.size / 8;

    for (size_t i = 0; i < blocks; ++i){
        uint64_t c = bytes_to_u64(input.data + i * 8);
        uint64_t m = power_modulo(c, d, n);
        u64_to_bytes(out.data + i * 8, m);
    }

    clear_buffer(&n, sizeof(n));
    clear_buffer(&d, sizeof(d));

    uint8_t pad_len = out.data[input.size - 1];
    if (pad_len > 0 && pad_len <= 8){
        bool valid = true;
        for (size_t i = input.size - pad_len; i < input.size; ++i){
            if (out.data[i] != pad_len){
                valid = false;
                break;
            }
        }
        if (valid){
            out.size = input.size - pad_len;
            clear_buffer(out.data + out.size, pad_len);
        }
        else{
            return 4;
        }
    }
    else{
        return 5;
    }
    return 0;
}
extern "C" int generate_key(MutBuffer* key) {
    if (!key || !key->data) return 1;

    MutBuffer& out = *key;

    if (!out.data || out.size < 32) return 1;

    std::random_device rd;

    uint64_t p = rd() % 20000 + 10000;
    while (!is_prime(p)) p = rd() % 20000 + 10000;

    uint64_t q = rd() % 20000 + 10000;
    while (!is_prime(q) || q == p) q = rd() % 20000 + 10000;

    uint64_t n = p * q;
    uint64_t phi = (p - 1) * (q - 1);

    uint64_t e = 3;
    while (e < phi) {
        if (nod(e, phi) == 1) break;
        e += 2;
    }

    uint64_t d = evklid_inverse(e, phi);

    u64_to_bytes(out.data, n);
    u64_to_bytes(out.data + 8, e);
    u64_to_bytes(out.data + 16, n);
    u64_to_bytes(out.data + 24, d);

    clear_buffer(&p, sizeof(p));
    clear_buffer(&q, sizeof(q));
    clear_buffer(&phi, sizeof(phi));

    out.size = 32;

    return 0; 
}