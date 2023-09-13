//
//  main.c
//  RC4 Implementation
//
//  Created by khaled salem on 11/23/17.
//  Copyright © 2017 khaled Fawzy. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <inttypes.h>

#include <stdio.h>
#include <string.h>


void password_accepted()
{
	execve("/bin/sh", 0, 0);
}
typedef unsigned long ULONG;

void rc4_init(unsigned char *s, unsigned char *key, unsigned long Len) //初始化函数
{
    int i =0, j = 0;
    char k[256] = {0};
    unsigned char tmp = 0;
    for (i=0;i<256;i++) {
        s[i] = i;
        k[i] = key[i%Len];
    }
    for (i=0; i<256; i++) {
        j=(j+s[i]+k[i])%256;
        tmp = s[i];
        s[i] = s[j];
        s[j] = tmp;
    }
 }

void rc4_crypt(unsigned char *s, unsigned char *Data, unsigned long Len) //加解密
{
    int i = 0, j = 0, t = 0;
    unsigned long k = 0;
    unsigned char tmp;
    for(k=0;k<Len;k++) {
        i=(i+1)%256;
        j=(j+s[i])%256;
        tmp = s[i];
        s[i] = s[j];
        s[j] = tmp;
        t=(s[i]+s[j])%256;
        Data[k] ^= s[t];
     }
} 

int main()
{ 
    unsigned char s[256] = {0};
    char key[256] = {"sharingiscaring"};
    char input[100];
    char pData[512]={0x45, 0xb5, 0xd3, 0x94, 0xf9, 0xb8, 0x55, 0x50, 0xdd, 0x3c, 0xa9, 0x86, 0x7b, 0x93, 0x2a, 0x21, 0x1c, 0x89, 0xb1, 0xf2, 0x87, 0x57, 0xe2, 0xf6, 0xa5, 0xa3, 0x64, 0x16, 0xcd, 0x7d};
    ULONG len = strlen(pData);

    
    rc4_init(s,(unsigned char *)key,strlen(key));

    rc4_crypt(s,(unsigned char *)pData,len);
    scanf("%30s",input);

    if (strncmp(input,pData,30)==0)
    {

    password_accepted(); 
    }
    return 0;
}



