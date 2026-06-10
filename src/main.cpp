#include "crypto_interface.h"
#include <dlfcn.h>
#include "plugin_loader.h"
#include <iostream>
#include <string>
#include <vector>
#include <cstring>
using namespace std;

#ifdef _WIN32
#include <windows.h>
#endif

void print_help(){
    cout << "           Справочная сводка по SilentChipher\n" 
        << "Флаги:\n" 
        << "    -a, --algorithm <название_алгоритма>   Выбор алгоритма для шифрования: Gronfeld; Skytale; Atbash; RSA; Caesar; Vigenere.\n" 
        << "    -m, --mode <режим_программы>           Выбор режима программы: encrypt; descrypt; generate-key.\n" 
        << "    -k, --key <название_файла>             Ввод пути к файлу ключа\n"
        << "    -i, --input <название_файла>           Ввыбор файла для шифрования, или '-' для ввода с консоли\n"
        << "    -o, --output <название_файла>          Выбор файла для вывода, или '-' для вывода в консоль\n"
        << "        --generate-key                     Генерация нового ключа\n"
        << "        --save-key                         Сохранение сгенерированного ключа в файл\n"
        << "    -h, --help                             Вывод данной справки\n";
}

bool parse_args(int argc, char* argv[], string& algo, string& mode, string& key_path, string& input_path, string& output_path, bool& gen_key, bool& save_key){
        for(int i = 1; i < argc; ++i){
            string arg = argv[i];
            if(arg == "-h" || arg == "--help") {mode = "help"; return true;}
            else if(arg == "-a" || arg == "--algorithm") {if(i+1 < argc) algo = argv[++i]; else return false;}
            else if (arg == "-m" || arg == "--mode") {if(i+1 < argc) mode = argv[++i]; else return false;}
            else if(arg == "-k" || arg == "--key") {if(i+1 < argc) key_path = argv[++i]; else return false;}
            else if(arg == "-i" || arg == "--input") {if(i+1 < argc) input_path = argv[++i]; else return false;}
            else if(arg == "-o" || arg == "--output") {if(i+1 < argc) output_path = argv[++i]; else return false;}
            else if(arg == "--generate-key") {gen_key = true;}
            else if(arg == "--save-key") {save_key = true;}
            else {return false;}
        }
        return true;
}

void secure_memory(void* ptr, size_t size) {
    if (!ptr || size == 0) return;
#ifdef _WIN32
    SecureZeroMemory(ptr, size);
#else
    explicit_bzero(ptr, size);
#endif
    free(ptr);
}

int main(int argc, char* argv[]){

    #ifdef _WIN32
        SetConsoleOutputCP(CP_UTF8);
        SetConsoleCP(CP_UTF8);
    #endif

    string algo, mode, key_path, input_path, output_path;
    bool gen_key = false;
    bool save_key = false;

    if (!parse_args(argc, argv, algo, mode, key_path, input_path, output_path, gen_key, save_key)) {
        std::cerr << "Ошибка: некорректные аргументы командной строки.\n";
        print_help();
        return 1;
    }

    if (argc < 2 || mode == "help" || algo.empty()){
        print_help();
        return 0;
    }

    try{
        void* handle = plugin_loader::load_plugin(algo);
        auto get_info = plugin_loader::get_symbol<const AlgorithmInfo*(*)()>(handle, "get_algorithm_info");
        const AlgorithmInfo* info = get_info();

        if (info && info->algorithm_name) {
            cout << "Загружен алгоритм: " << info->algorithm_name << ", его размер ключа: " << info->key_size << endl;
        } else {
            cout << "Загружен алгоритм: " << algo << " (информация недоступна)" << endl;
        }

        plugin_loader::unload_plugin(handle);
    }catch(const exception& mistake){
        cerr << "Ошибка: " << mistake.what() << endl;
        return 1;
    }
    
    return 0;
}
