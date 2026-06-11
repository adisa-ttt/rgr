#include "io_manager.h"
#include <fstream>
#include <iostream>
#include <stdexcept>

#ifdef _WIN32
    #include<io.h>
    #include <fcntl.h>
#endif

using namespace std;

namespace io_manager{

    vector<uint8_t> read_binary_data(const string& path){
        if (path == "-"){
            #ifdef _WIN32
                _setmode(_fileno(stdin), _O_BINARY);
            #endif
        
            vector<uint8_t> data;
            uint8_t byte;
            while(cin.read(reinterpret_cast<char*>(&byte), 1)){
                data.push_back(byte);
            }
        return data;
        }

        ifstream file(path, ios::in | ios::binary);
        if(!file) throw runtime_error ("Не удалось открыть файл для чтения: " + path);

        file.seekg(0, ios::end);
        size_t size = file.tellg();
        file.seekg(0, ios::beg);

        vector<uint8_t> data(size);

        if(size == 0) throw runtime_error ("Файл " + path + " пуст.");

            if (!file.read(reinterpret_cast<char*>(data.data()), size)) throw runtime_error("Ошибка чтения файла ключа " + path + ".");
        return data;
    }

    void write_binary_data(const string& path, const vector<uint8_t>& data){
        if (path == "-"){
            #ifdef _WIN32
                _setmode(_fileno(stdout), _O_BINARY);
            #endif

            cout.write(reinterpret_cast<const char*>(data.data()), data.size());
            cout.flush();
            return;
        }
        ofstream file(path, ios::out | ios::binary);
        if (!file) {
            throw std::runtime_error("Не удалось открыть файл для записи: " + path);
        }
        file.write(reinterpret_cast<const char*>(data.data()), data.size());
    }
}