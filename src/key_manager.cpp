#include "key_manager.h"
#include <stdexcept>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#else
#include <sys/random.h>
#include <cstring>
#endif

using namespace std;

namespace key_manager{

vector<uint8_t> generate_secure_key(size_t key_size){
    vector<uint8_t> key(key_size);

    #ifdef _WIN32
        if (!BCRYPT_SUCCESS(BCryptGenRandom(nullptr, key.data(), static_cast<ULONG>(key_size), BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
            throw runtime_error("Ошибка генерации ключа Windows BCrypt");}
    #else
        if(getrandom(key.data(), key_size, 0) != static_cast<ssize_t>(key_size)){
            throw runtime_error("Ошибка генерации ключа Linux getrandom: " + string(strerror(errno)));}
    #endif

    return key;
}
}