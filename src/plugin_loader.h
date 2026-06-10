#ifndef PLUGIN_LOADER_H
#define PLUGIN_LOADER_H

#include <string>
#include <stdexcept>

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace plugin_loader {
    void* load_plugin(const std::string& algorithm_name);
    void unload_plugin(void* handle);
    
    template <typename T>
    T get_symbol(void* handle, const std::string& symbol_name);
}

template <typename T>
T plugin_loader::get_symbol(void* handle, const std::string& symbol_name) {
    if (!handle) {
        throw std::runtime_error("Недействительный дескриптор библиотеки.");
    }
    
#ifdef _WIN32
    T symbol = reinterpret_cast<T>(GetProcAddress((HMODULE)handle, symbol_name.c_str()));
#else
    T symbol = reinterpret_cast<T>(dlsym(handle, symbol_name.c_str()));
#endif

    if (!symbol) {
        throw std::runtime_error("Функция '" + symbol_name + "' не найдена в библиотеке.");
    }
    return symbol;
}

#endif 