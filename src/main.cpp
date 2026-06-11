#include "crypto_interface.h"
#include "plugin_loader.h"
#include "key_manager.h"
#include "io_manager.h"
#include "crypto_operations.h"
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
        << "    -a, --algorithm <название_алгоритма>   Выбор алгоритма для шифрования: skytale, gronsfeld, atbash, rsa, caesar, vigenere.\n" 
        << "    -m, --mode <режим_программы>           Выбор режима программы: encrypt; descrypt; generate-key.\n" 
        << "    -k, --key <название_файла>             Ввод пути к файлу ключа\n"
        << "    -i, --input <название_файла>           Выбор файла для шифрования, или '-' для ввода с консоли\n"
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
        cerr << "Ошибка: некорректные аргументы командной строки.\n";
        print_help();
        return 1;
    }

    if (argc < 2 || mode == "help" || algo.empty()){
        print_help();
        return 0;
    }

    try{
        vector<string> supported_algos = {"caesar", "vigenere", "atbash", "rsa", "Skytale", "Gronsfeld"};
        bool is_supported = false;
        for (const auto& a : supported_algos) {
            if (a == algo) { 
                is_supported = true; 
                break; }
        }
        if (!is_supported) throw runtime_error("Неподдерживаемый алгоритм: " + algo + ". Доступные: Skytale, Gronsfeld, atbash, rsa, caesar, vigenere.");

        void* handle = plugin_loader::load_plugin(algo);
        auto get_info = plugin_loader::get_symbol<const AlgorithmInfo*(*)()>(handle, "get_algorithm_info");
        const AlgorithmInfo* info = get_info();

        if (!info) {
            cerr << algo << "' не вернула информацию" << endl;
            plugin_loader::unload_plugin(handle);
            return 1;
        }


        cout << "Загружен алгоритм: " << info->algorithm_name << ", его размер ключа: " << info->key_size << endl;
        
        if (!handle) {
            cerr << "Ошибка: не удалось загрузить библиотеку '" << algo << "'" << endl;
            return 1;
        }

        if (!get_info) {
            cerr << "Ошибка: функция get_algorithm_info не найдена в библиотеке" << endl;
            plugin_loader::unload_plugin(handle);
            return 1;
        }

        if (!info) {
            cerr << "Ошибка: get_algorithm_info вернула nullptr" << endl;
            plugin_loader::unload_plugin(handle);
            return 1;
        }

        if (!info->algorithm_name) {
            cerr << "Ошибка: algorithm_name не инициализирован в библиотеке" << endl;
            plugin_loader::unload_plugin(handle);
            return 1;
        }


        cout << "Загружен алгоритм: " << info->algorithm_name << ", его размер ключа: " << info->key_size << endl;

        vector<uint8_t> key;
        if(gen_key){
            key = key_manager::generate_secure_key(info->key_size);
            cout << "Ключ сгенерирован." << endl;
            
            if(save_key){
                string save_path = output_path.empty() ? "-" :output_path;
                io_manager::write_binary_data(save_path, key);
            }

            secure_memory(key.data(), key.size());
            plugin_loader::unload_plugin(handle);
            return 0;

        } else {
            string actual_key_path = key_path.empty() ? "-" : key_path;
            key = io_manager::read_binary_data(actual_key_path);
            cout << "Ключ прочитан." << endl;
        }

        if (mode == "encrypt" || mode == "decrypt"){
            if (input_path.empty()) throw runtime_error("Не указан входной файл для режима " + mode);
        
            vector<uint8_t> input_data = io_manager::read_binary_data(input_path);
            vector<uint8_t> output_data;

            if(mode == "encrypt"){
                output_data = crypto_operations::encrypt(handle, key, input_data);
            } else if (mode == "decrypt"){
                output_data = crypto_operations::decrypt(handle, key, input_data);
            } else throw runtime_error ("Ошибка: неизвестный режим работы программы.");

            string out_path = output_path.empty() ? "-" : output_path;
            io_manager::write_binary_data(out_path, output_data);

            secure_memory(input_data.data(), input_data.size());
            secure_memory(output_data.data(), output_data.size());
        }
        
        secure_memory(key.data(), key.size());
            plugin_loader::unload_plugin(handle);

        } catch(const exception& mistake){
        cerr << "Ошибка: " << mistake.what() << endl;
        return 1;
    }
    
    return 0;
}
