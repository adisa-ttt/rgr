#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <dlfcn.h>
#include <iomanip>
#include <cstdlib>
#include <ctime>
#include "../include/cryptoInterface.h"

using namespace std;

void printHex(const uint8_t* data, size_t size) {
    for (size_t i = 0; i < size; i++)
        cout << hex << uppercase << setw(2) << setfill('0') << (int)data[i] << " ";
    cout << dec << endl;
}

vector<uint8_t> hexToBytes(const string& hex) {
    vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i++) {
        if (hex[i] == ' ') continue;
        if (i + 1 < hex.length()) {
            string byteStr = hex.substr(i, 2);
            bytes.push_back((uint8_t)strtol(byteStr.c_str(), NULL, 16));
            i++;
        }
    }
    return bytes;
}

string getErrorMessage(int code) {
    if (code == 1) return "Недостаточно места в буфере.";
    if (code == 2) return "Неверный ключ.";
    if (code == 3) return "Длина данных не кратна ключу.";
    return "Неизвестная ошибка (код " + to_string(code) + ").";
}

string generateKey(int algo) {
    srand((unsigned)time(NULL));
    if (algo == 1) {
        string key;
        int length = 3 + rand() % 4;
        for (int i = 0; i < length; i++)
            key += (char)('1' + rand() % 9);
        return key;
    } else {
        return to_string(2 + rand() % 8);
    }
}

void runCipher(const string& libPath, bool isScytale) {
    void* handle = dlopen(libPath.c_str(), RTLD_LAZY);
    if (!handle) { cout << "Ошибка: библиотека не найдена.\n"; return; }

    typedef int (*ProcessFunc)(ConstBuffer, ConstBuffer, MutBuffer*);
    typedef size_t (*SizeFunc)(size_t, int);

    ProcessFunc doEncrypt = (ProcessFunc)dlsym(handle, "encrypt");
    ProcessFunc doDecrypt = (ProcessFunc)dlsym(handle, "decrypt");
    SizeFunc getOutSize = (SizeFunc)dlsym(handle, "get_output_size");

    if (!doEncrypt || !doDecrypt || !getOutSize) {
        cout << "Ошибка: функции не найдены.\n";
        dlclose(handle);
        return;
    }

    int mode;
    cout << "1. Шифровать текст\n2. Дешифровать текст\n3. Шифровать файл\n4. Дешифровать файл\nВыбор: ";
    cin >> mode;
    if (mode < 1 || mode > 4) { dlclose(handle); return; }

    string keyStr;
    cout << "Ключ (Enter для генерации): ";
    cin.ignore();
    getline(cin, keyStr);

    if (keyStr.empty()) {
        keyStr = generateKey(isScytale ? 2 : 1);
        cout << "Сгенерирован ключ: " << keyStr << endl;
    }
    ConstBuffer key = {(const uint8_t*)keyStr.c_str(), keyStr.size()};

    vector<uint8_t> data;
    if (mode == 1) {
        string text; cout << "Текст: "; getline(cin, text);
        data.assign(text.begin(), text.end());
    } else if (mode == 2) {
        string hex; cout << "HEX: "; getline(cin, hex);
        data = hexToBytes(hex);
        if (data.empty()) { cout << "Ошибка: некорректный HEX.\n"; dlclose(handle); return; }
    } else {
        string path; cout << "Путь к файлу: "; getline(cin, path);
        if (path.empty()) { cout << "Ошибка: путь пуст.\n"; dlclose(handle); return; }
        ifstream f(path, ios::binary);
        if (!f) { cout << "Ошибка: файл не найден.\n"; dlclose(handle); return; }
        data.assign(istreambuf_iterator<char>(f), {});
    }

    if (isScytale && (mode == 1 || mode == 3)) {
        int m = atoi(keyStr.c_str());
        if (m > 1) {
            size_t rem = data.size() % m;
            if (rem != 0) data.resize(data.size() + (m - rem), ' ');
        }
    }

    ConstBuffer input = {data.data(), data.size()};
    size_t outSizeVal = getOutSize(data.size(), mode);
    vector<uint8_t> outBuf(outSizeVal);
    MutBuffer outMut = {outBuf.data(), outSizeVal};

    int res = (mode == 1 || mode == 3) ? doEncrypt(key, input, &outMut) : doDecrypt(key, input, &outMut);

    if (res != 0) {
        cout << "Ошибка: " << getErrorMessage(res) << endl;
        dlclose(handle);
        return;
    }

    if (mode == 1) {
        cout << "HEX: "; printHex(outBuf.data(), outBuf.size());
    } else if (mode == 2) {
        string result(outBuf.begin(), outBuf.end());
        if (isScytale) {
            size_t last = result.find_last_not_of(' ');
            if (last != string::npos) result = result.substr(0, last + 1);
        }
        cout << "Текст: " << result << endl;
    } else {
        string outPath; cout << "Сохранить в файл: "; getline(cin, outPath);
        if (outPath.empty()) { cout << "Ошибка: путь пуст.\n"; }
        else {
            ofstream f(outPath, ios::binary);
            if (!f) { cout << "Ошибка: не удалось создать файл.\n"; }
            else {
                f.write((char*)outBuf.data(), outBuf.size());
                cout << "Готово. Файл сохранен.\n";
            }
        }
    }
    dlclose(handle);
}

int main() {
    try {
        int choice;
        while (true) {
            cout << "\n1. Гронсфельд\n2. Скитала\n3. Генератор ключей\n0. Выход\nВыбор: ";
            cin >> choice;
            if (cin.fail()) { cin.clear(); cin.ignore(1000, '\n'); cout << "Введите число.\n"; continue; }
            
            if (choice == 0) break;
            else if (choice == 1) runCipher("./libgronsfeld.so", false);
            else if (choice == 2) runCipher("./libscytale.so", true);
            else if (choice == 3) {
                int algo;
                cout << "1. Гронсфельд\n2. Скитала\nВыбор: ";
                cin >> algo;
                if (algo == 1 || algo == 2) cout << "Ключ: " << generateKey(algo) << endl;
                else cout << "Неверный выбор.\n";
            }
            else cout << "Неверный выбор.\n";
        }
    } catch (const exception& e) {
        cout << "Критическая ошибка: " << e.what() << endl;
    }
    return 0;
}
