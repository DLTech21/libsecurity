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
    EncryptMsg(pInData, nInLen, &pOut, nOutLen);
    //cout<<pOut;
    printf("%s", pOut);
    Free(pOut);
    return 0;
}