#include "plugin_loader.h"
#include <string>
#include <stdexcept>

using namespace std;

namespace plugin_loader{
    void* load_plugin(const string& algorithm_name){
        #ifdef _WIN32
            string lib_name = algorithm_name + ".dll";
            HMODULE handle = LoadLibraryA(lib_name.c_str());
            if(!handle){
                throw runtime_error("Не удалось загрузить библиотеку " + lib_name);
            }
            return reinterpret_cast<void*>(handle);
        #else
            string lib_name = "lib" + algorithm_name + ".so";
            void* handle = dlopen(lib_name.c_str(), RTLD_NOW);
            if(!handle){
                const char* err = dlerror();
                string error_message = err ? err : "неизвестная ошибка";
                throw runtime_error("Не удалось загрузить библиотеку " + lib_name + ". Ошибка: " + error_message);
            }
            return handle;
        #endif
    }

    void unload_plugin(void* handle){
        if(!handle) return;

        #ifdef _WIN32
            FreeLibrary((HMODULE)handle);
        #else
            dlclose(handle);
        #endif
    }
}
