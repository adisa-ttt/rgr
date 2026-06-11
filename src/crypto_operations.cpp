#include "crypto_operations.h"
#include "crypto_interface.h"
#include "plugin_loader.h"
#include <stdexcept>
#include <vector>
using namespace std;

vector<uint8_t> encrypt(void* handle, const std::vector<uint8_t>& key, const std::vector<uint8_t>& input){
    auto get_size = plugin_loader::get_symbol<size_t(*)(size_t, int)>(handle, "get_output_size");
    auto enc = plugin_loader::get_symbol<int(*)(ConstBuffer, ConstBuffer, MutBuffer*)>(handle, "encrypt");

    size_t out_size = get_size(input.size(), 1);
    vector<uint8_t> output(out_size);

    ConstBuffer key_buf = {key.data(), key.size()};
    ConstBuffer in_buf = {input.data(), input.size()};
    MutBuffer out_buf = {output.data(), output.size()};

    int result = enc(key_buf, in_buf, &out_buf);
    if(result != 0) throw runtime_error("Ошибка шифрования. Код: " + std::to_string(result));
    return output;
}

vector<uint8_t> decrypt(void* handle, const std::vector<uint8_t>& key, const std::vector<uint8_t>& input){
    auto get_size = plugin_loader::get_symbol<size_t(*)(size_t, int)>(handle, "get_output_size");
    auto dec = plugin_loader::get_symbol<int(*)(ConstBuffer, ConstBuffer, MutBuffer*)>(handle, "encrypt");

    size_t out_size = get_size(input.size(), 2);
    vector<uint8_t> output(out_size);

    ConstBuffer key_buf = {key.data(), key.size()};
    ConstBuffer in_buf = {input.data(), input.size()};
    MutBuffer out_buf = {output.data(), output.size()};

    int result = dec(key_buf, in_buf, &out_buf);
    if(result != 0) throw runtime_error("Ошибка расшифрования. Код: " + std::to_string(result));
    return output;
}
