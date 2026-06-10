#ifndef PLUGINLOADER_H
#define PLUGINLOADER_H
#include <string>
#include <stdexcept>
using namespace std;

namespace plugin_loader{
    void* load_plugin(const string& algorithm_name);
    void unload_plugin(void* handle);

    template <typename T>
    T get_symbol(void* handle, const string& symbol_name);
}

template <typename T>
T plugin_loader::get_symbol(void* handle, const string& symbol_name){
    if(!handle){
        throw runtime_error ("Недействительный дескриптор библиотека.");
    }

#ifdef _WIN32
    #include <windows.h>
    T symbol = reinterpret_cast<T>(GetProcAddress((HMODULE)handle, symbol_name.c_str()));
#else
    #include <dlfcn.h>
    T symbol = reinterpret_cast<T>(dlsym(handle, symbol_name.c_str()));
#endif

if (!symbol) {
        throw runtime_error("Функция " + symbol_name + " не найдена.");
    }

    return symbol;

}

#endif