#include "crypto_interface.h"
#include <random>

static constexpr size_t RSA_KEY_SIZE = 32;
static constexpr size_t PLAIN_BLOCK_SIZE = 7;
static constexpr size_t CIPHER_BLOCK_SIZE = 8;

static void clear_buffer(void* ptr, size_t size) {
    volatile uint8_t* p = reinterpret_cast<volatile uint8_t*>(ptr);
    while (size--) *p++ = 0;
}

static bool is_prime(uint64_t n) {
    if (n < 2) return false;
    if (n == 2 || n == 3) return true;
    if (n % 2 == 0) return false;
    for (uint64_t i = 3; i <= n / i; i += 2) {
        if (n % i == 0) return false;
    }
    return true;
}

static uint64_t gcd(uint64_t a, uint64_t b) {
    while (b) {
        uint64_t t = b;
        b = a % b;
        a = t;
    }
    return a;
}

static uint64_t add_mod(uint64_t a, uint64_t b, uint64_t mod) {
    return (b >= mod - a) ? (a + b - mod) : (a + b);
}

static uint64_t mul_mod(uint64_t a, uint64_t b, uint64_t mod) {
    uint64_t res = 0;
    a %= mod;
    b %= mod;
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
    int64_t old_r = static_cast<int64_t>(e);
    int64_t r = static_cast<int64_t>(phi);
    int64_t old_s = 1;
    int64_t s = 0;

    while (r != 0) {
        int64_t q = old_r / r;

        int64_t next_r = old_r - q * r;
        old_r = r;
        r = next_r;

        int64_t next_s = old_s - q * s;
        old_s = s;
        s = next_s;
    }

    if (old_s < 0) old_s += static_cast<int64_t>(phi);
    return static_cast<uint64_t>(old_s);
}

static uint64_t bytes_to_u64(const uint8_t* b) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | b[i];
    return v;
}

static void u64_to_bytes(uint8_t* b, uint64_t v) {
    for (int i = 7; i >= 0; --i) {
        b[i] = static_cast<uint8_t>(v & 0xFF);
        v >>= 8;
    }
}

static uint64_t plain_block_to_u64(const uint8_t* b) {
    uint64_t v = 0;
    for (size_t i = 0; i < PLAIN_BLOCK_SIZE; ++i) v = (v << 8) | b[i];
    return v;
}

static void u64_to_plain_block(uint8_t* b, uint64_t v) {
    for (int i = static_cast<int>(PLAIN_BLOCK_SIZE) - 1; i >= 0; --i) {
        b[i] = static_cast<uint8_t>(v & 0xFF);
        v >>= 8;
    }
}

extern "C" const AlgorithmInfo* get_algorithm_info() {
    static AlgorithmInfo info = {"RSA-64", RSA_KEY_SIZE};
    return &info;
}

extern "C" size_t get_output_size(size_t input_size, int operation_type) {
    if (operation_type == 1) {
        size_t pad = PLAIN_BLOCK_SIZE - (input_size % PLAIN_BLOCK_SIZE);
        if (pad == 0) pad = PLAIN_BLOCK_SIZE;
        return ((input_size + pad) / PLAIN_BLOCK_SIZE) * CIPHER_BLOCK_SIZE;
    }

    if (input_size % CIPHER_BLOCK_SIZE != 0) return 0;
    return (input_size / CIPHER_BLOCK_SIZE) * PLAIN_BLOCK_SIZE;
}

extern "C" int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (!key.data || !output || !output->data) return 1;
    if (input.size > 0 && !input.data) return 1;
    if (key.size < RSA_KEY_SIZE) return 1;

    size_t need = get_output_size(input.size, 1);
    if (output->size < need) return 1;

    uint64_t n = bytes_to_u64(key.data);
    uint64_t e = bytes_to_u64(key.data + 8);
    if (!n || !e) return 2;

    size_t pad_len = PLAIN_BLOCK_SIZE - (input.size % PLAIN_BLOCK_SIZE);
    if (pad_len == 0) pad_len = PLAIN_BLOCK_SIZE;

    size_t blocks = need / CIPHER_BLOCK_SIZE;
    for (size_t i = 0; i < blocks; ++i) {
        uint8_t blk[PLAIN_BLOCK_SIZE] = {0};
        for (size_t j = 0; j < PLAIN_BLOCK_SIZE; ++j) {
            size_t idx = i * PLAIN_BLOCK_SIZE + j;
            blk[j] = (idx < input.size) ? input.data[idx] : static_cast<uint8_t>(pad_len);
        }

        uint64_t m = plain_block_to_u64(blk);
        if (m >= n) return 3;

        u64_to_bytes(output->data + i * CIPHER_BLOCK_SIZE, pow_mod(m, e, n));
        clear_buffer(blk, sizeof(blk));
    }

    output->size = need;
    return 0;
}

extern "C" int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output) {
    if (!key.data || !input.data || !output || !output->data) return 1;
    if (!input.size || input.size % CIPHER_BLOCK_SIZE || key.size < RSA_KEY_SIZE) return 1;

    size_t max_plain_size = get_output_size(input.size, 2);
    if (output->size < max_plain_size) return 2;

    uint64_t n = bytes_to_u64(key.data + 16);
    uint64_t d = bytes_to_u64(key.data + 24);
    if (!n || !d) return 3;

    size_t blocks = input.size / CIPHER_BLOCK_SIZE;
    for (size_t i = 0; i < blocks; ++i) {
        uint64_t c = bytes_to_u64(input.data + i * CIPHER_BLOCK_SIZE);
        uint64_t m = pow_mod(c, d, n);
        u64_to_plain_block(output->data + i * PLAIN_BLOCK_SIZE, m);
    }

    uint8_t pad = output->data[max_plain_size - 1];
    if (!pad || pad > PLAIN_BLOCK_SIZE) return 5;

    for (size_t i = max_plain_size - pad; i < max_plain_size; ++i) {
        if (output->data[i] != pad) return 4;
    }

    output->size = max_plain_size - pad;
    clear_buffer(output->data + output->size, pad);
    clear_buffer(&n, sizeof(n));
    clear_buffer(&d, sizeof(d));
    return 0;
}

extern "C" int generate_key(MutBuffer* key) {
    if (!key || !key->data || key->size < RSA_KEY_SIZE) return 1;

    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist(0x10000000ULL, 0x7FFFFFFFULL);

    auto gen_prime = [&]() {
        uint64_t p;
        do {
            p = dist(gen) | 1ULL;
        } while (!is_prime(p));
        return p;
    };

    uint64_t p = 0;
    uint64_t q = 0;
    uint64_t n = 0;
    uint64_t phi = 0;
    uint64_t e = 65537;

    do {
        p = gen_prime();
        q = gen_prime();
        n = p * q;
        phi = (p - 1) * (q - 1);
    } while (p == q || n <= 0x0100000000000000ULL || gcd(e, phi) != 1);

    uint64_t d = mod_inverse(e, phi);

    u64_to_bytes(key->data, n);
    u64_to_bytes(key->data + 8, e);
    u64_to_bytes(key->data + 16, n);
    u64_to_bytes(key->data + 24, d);

    clear_buffer(&p, sizeof(p));
    clear_buffer(&q, sizeof(q));
    clear_buffer(&phi, sizeof(phi));

    key->size = RSA_KEY_SIZE;
    return 0;
}
