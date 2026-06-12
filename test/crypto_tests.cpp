#include "crypto_operations.h"
#include "plugin_loader.h"

#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

static std::vector<uint8_t> bytes(const std::string& text) {
    return {text.begin(), text.end()};
}

static std::vector<uint8_t> rsa_key() {
    return {
        0x01, 0xaa, 0x53, 0x5e, 0x84, 0xdf, 0x57, 0x3f,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
        0x01, 0xaa, 0x53, 0x5e, 0x84, 0xdf, 0x57, 0x3f,
        0x01, 0x44, 0xec, 0x87, 0x64, 0x97, 0x05, 0x71
    };
}

static bool test_round_trip(const std::string& algorithm,
                            const std::string& name,
                            const std::vector<uint8_t>& key,
                            const std::vector<uint8_t>& input) {
    try {
        void* plugin = plugin_loader::load_plugin(algorithm);

        std::vector<uint8_t> encrypted = crypto_operations::encrypt(plugin, key, input);
        std::vector<uint8_t> decrypted = crypto_operations::decrypt(plugin, key, encrypted);

        plugin_loader::unload_plugin(plugin);

        if (decrypted != input) {
            std::cerr << "[FAIL] " << name << ": результат не совпал с исходными данными\n";
            return false;
        }

        std::cout << "[ OK ] " << name << '\n';
        return true;
    } catch (const std::exception& error) {
        std::cerr << "[FAIL] " << name << ": " << error.what() << '\n';
        return false;
    }
}

int main() {
    int failed = 0;

    failed += test_round_trip("atbash", "atbash: text", {}, bytes("Hello, Atbash!")) ? 0 : 1;
    failed += test_round_trip("atbash", "atbash: russian", {}, bytes("Привет, мир!")) ? 0 : 1;
    failed += test_round_trip("atbash", "atbash: binary", {}, {0x00, 0x01, 0x7f, 0x80, 0xff}) ? 0 : 1;

    const std::vector<uint8_t> key = rsa_key();
    failed += test_round_trip("rsa", "rsa: short text", key, bytes("abc")) ? 0 : 1;
    failed += test_round_trip("rsa", "rsa: block size text", key, bytes("1234567")) ? 0 : 1;
    failed += test_round_trip("rsa", "rsa: binary", key, {0x00, 0xff, 0x10, 0x20, 0x7f, 0x80}) ? 0 : 1;

    if (failed != 0) {
        std::cerr << "Failed tests: " << failed << '\n';
        return 1;
    }

    std::cout << "All tests passed.\n";
    return 0;
}
