#include "key_manager.h"
#include <stdexcept>
#include <vector>
#include <fstream>
#include <iostream>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#include <io.h>      
#include <fcntl.h> 
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

vector<uint8_t> read_key_from_file(const std::string& file_path){
    ifstream file(file_path, ios::in | ios::binary);
    if(!file.is_open()) throw runtime_error("Не удалось открыть файл ключа " + file_path + ".");

    file.seekg(0, ios::end);
    size_t size = file.tellg();
    file.seekg(0, ios::beg);

    if(size == 0) throw runtime_error ("Файл ключа" + file_path + "пуст.");

    vector<uint8_t> key(size);
        if (!file.read(reinterpret_cast<char*>(key.data()), size)) throw runtime_error("Ошибка чтения файла ключа " + file_path + ".");
    return key;
}

vector<uint8_t> read_key_from_stdin(){
    #ifdef _WIN32
        if (_setmode(_fileno(stdin), _O_BINARY) == -1) throw runtime_error("Не удалось переключить поток ввода в бинарный режим (Windows)");
    #endif

    vector<uint8_t> key;
    uint8_t byte;

    while(cin.read(reinterpret_cast<char*>(&byte), 1)){
        key.push_back(byte);
    }

    if (key.empty()) throw runtime_error("Поток ввода пуст или произошла ошибка чтения");

    #ifdef _WIN32
        setmode(_fileno(stdin), _O_TEXT);
    #endif

    return key;
}
}