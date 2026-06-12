#include "crypto_interface.h"
#include <random>

static void clear_buffer(void* ptr, size_t size) {
    volatile uint8_t* p = reinterpret_cast<volatile uint8_t*>(ptr);
    while (size--) *p++ = 0;
}

static bool is_prime(uint64_t n) {
    if (n < 2) return false;
    if (n == 2 || n == 3) return true;
    if (n % 2 == 0) return false;
    for (uint64_t i = 3; i * i <= n; i += 2)
        if (n % i == 0) return false;
    return true;
}

static uint64_t gcd(uint64_t a, uint64_t b) {
    while (b) { uint64_t t = b; b = a % b; a = t; }
    return a;
}

static uint64_t add_mod(uint64_t a, uint64_t b, uint64_t mod) {
    return (b >= mod - a) ? (a + b - mod) : (a + b);
}

static uint64_t mul_mod(uint64_t a, uint64_t b, uint64_t mod) {
    uint64_t res = 0;
    a %= mod; b %= mod;
    while (b) {
        if (b & 1) res = add_mod(res, a, mod);
        a = add_mod(a, a, mod);
        b >>= 1;
    }
    return res;
}

static uint64_t pow_mod(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t res = 1;
    base %= mod;
    while (exp) {
        if (exp & 1) res = mul_mod(res, base, mod);
        base = mul_mod(base, base, mod);
        exp >>= 1;
    }
    return res;
}

static uint64_t mod_inverse(uint64_t e, uint64_t phi) {
    uint64_t m0 = phi, y = 0, x = 1;
    if (phi == 1) return 0;
    while (e > 1) {
        uint64_t q = e / phi;
        uint64_t t = phi;
        phi = e % phi;
        e = t;
        t = y;
        uint64_t qy = mul_mod(q % m0, t % m0, m0);
        y = (x >= qy) ? (x - qy) : (m0 - (qy - x));
        x = t;
    }
    return (x >= m0) ? (x - m0) : x;
}

static uint64_t bytes_to_u64(const uint8_t* b) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | b[i];
    return v;
}

static void u64_to_bytes(uint8_t* b, uint64_t v) {
    for (int i = 7; i >= 0; --i) { b[i] = v & 0xFF; v >>= 8; }
}

extern "C" const AlgorithmInfo* get_algorithm_info() {
    static AlgorithmInfo info = {"RSA-64", 32};
    return &info;
}

extern "C" size_t get_output_size(size_t input_size, int operation_type) {
    return (operation_type == 1) ? ((input_size / 8) + 1) * 8 : input_size;
}

extern "C" int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (!key.data || !input.data || !output || !output->data) return 1;
    
    size_t need = get_output_size(input.size, 1);
    if (output->size < need || key.size < 32) return 1;

    uint64_t n = bytes_to_u64(key.data);
    uint64_t e = bytes_to_u64(key.data + 8);
    if (!n || !e) return 2;

    size_t blocks = need / 8;
    size_t pad_len = need - input.size;

    for (size_t i = 0; i < blocks; ++i) {
        uint8_t blk[8] = {0};
        for (size_t j = 0; j < 8; ++j) {
            size_t idx = i * 8 + j;
            blk[j] = (idx < input.size) ? input.data[idx] : (uint8_t)pad_len;
        }
        uint64_t m = bytes_to_u64(blk);
        if (m >= n) m %= n; 
        u64_to_bytes(output->data + i * 8, pow_mod(m, e, n));
        clear_buffer(blk, 8); 
    }
    output->size = need;
    return 0;
}

extern "C" int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (!key.data || !input.data || !output || !output->data) return 1;
    if (!input.size || input.size % 8 || key.size < 32) return 1;
    if (output->size < input.size) return 2;

    uint64_t n = bytes_to_u64(key.data + 16);
    uint64_t d = bytes_to_u64(key.data + 24);
    if (!n || !d) return 3;

    size_t blocks = input.size / 8;
    for (size_t i = 0; i < blocks; ++i) {
        uint64_t c = bytes_to_u64(input.data + i * 8);
        u64_to_bytes(output->data + i * 8, pow_mod(c, d, n));
    }

    clear_buffer(&n, sizeof(n));
    clear_buffer(&d, sizeof(d));

    uint8_t pad = output->data[input.size - 1];
    if (!pad || pad > 8) return 5;

    for (size_t i = input.size - pad; i < input.size; ++i)
        if (output->data[i] != pad) return 4;

    output->size = input.size - pad;
    clear_buffer(output->data + output->size, pad); 
    return 0;
}

extern "C" int generate_key(MutBuffer* key) {
    if (!key || !key->data || key->size < 32) return 1;

    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist(0x80000000ULL, 0xFFFFFFFFULL);

    auto gen_prime = [&]() {
        uint64_t p;
        do { p = dist(gen); } while (!is_prime(p));
        return p;
    };

    uint64_t p, q, n;
    do {
        p = gen_prime();
        q = gen_prime();
        n = p * q;
    } while (n < 0x8000000000000000ULL || p == q);

    uint64_t phi = (p - 1) * (q - 1);
    uint64_t e = 65537;
    if (gcd(e, phi) != 1) { e = 3; while (gcd(e, phi) != 1) e += 2; }
    uint64_t d = mod_inverse(e, phi);

    u64_to_bytes(key->data, n);
    u64_to_bytes(key->data + 8, e);
    u64_to_bytes(key->data + 16, n);
    u64_to_bytes(key->data + 24, d);
    
    clear_buffer(&p, sizeof(p));
    clear_buffer(&q, sizeof(q));
    clear_buffer(&phi, sizeof(phi));
    
    key->size = 32;
    return 0;
}