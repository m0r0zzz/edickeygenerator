#include "Cipher.hpp"
#include <iostream>
#include <iomanip>
#include <string>

using namespace std;

void print_help(char* nm){
    cout << "EDIC ID stream transforming utility.\nUsage\n\t" << nm << " <action> <password>\n\n";
    cout << "Actions:\n e - encrypt (s/n -> ID)\n d - decrypt (ID -> s/n)";
}

int main(int argc, char** argv){
    hash256 passwd;

    if(argc != 3){
        print_help(argv[0]);
        return 0;
    }

    string sp = argv[2];
    passwd = HashFunc(sp.c_str(), sp.length());
    bool way = true;
    string act = argv[1];
    if(act == "e") way = true;
    else if(act == "d") way = false;
    else{
        cout << "Bad action format" << endl;
        return -1;
    }
    uint64_t data;
    cin >> data;
    data = CipherFunc(data, passwd, way);

    cout << data << endl;

    return 0;
}


