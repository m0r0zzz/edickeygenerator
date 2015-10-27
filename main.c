#include "cipher.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void print_help(char* nm){
    printf("EDIC ID stream transforming utility.\nUsage\n\t%s <action> <password>\n", nm);
}


int main(int argc, char** argv){
    if(argc != 3){
        print_help(argv[0]);
        return 0;
    }

    hash256 passwd = HashFunc(argv[2], strlen(argv[2]));
    uint8_t way = 1; //encrypt
    if(!strcmp(argv[1], "e")) way = 1;
    else if(!strcmp(argv[1], "d")) way = 0;
    else{
        printf("Bad action format\n");
        return -1;
    }
    uint64_t data;
    scanf("%lld\n", &data);
    data = CipherFunc(data, passwd, way);

    printf("%lld\n", &data);

    return 0;
}
