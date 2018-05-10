//
// Created by Donal Tong on 16/5/16.
//

#include "security.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
int main(int argc, char *argv[])
{
    const char* pInData = argv[1];
    uint32_t nInLen = strlen(pInData);
    char* pOut;
    uint32_t nOutLen;
    DecryptMsg(pInData, nInLen, &pOut, nOutLen);
    //cout<<pOut;
    printf("%s", pOut);
    Free(pOut);
    return 0;
}

//g++ -fPIC -shared -c aes_core.cpp base64.cpp md5.cpp security.cpp
//g++ -fPIC -shared -o libsecurity.so aes_core.o base64.o md5.o security.o