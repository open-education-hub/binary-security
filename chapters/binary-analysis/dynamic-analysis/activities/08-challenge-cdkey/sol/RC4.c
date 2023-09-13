//
//  RC4.c
//  RC4
//
//  Created by khaled salem on 11/23/17.
//  Copyright © 2017 khaled Fawzy. All rights reserved.
//
#include "RC4.h"

void RC4(unsigned char* data,long dataLen, unsigned char* key, long keyLen,unsigned char* result)
/* Function to encrypt data represented in array of char "data" with length represented in dataLen using key which is represented in "Key" with length represented in keyLen, and result will be stored in result */
{
    unsigned char T[256];
    unsigned char S[256];
    unsigned char  tmp; // to be used in swaping
    int j = 0,t= 0,i= 0;
   
    
    /* S & K initialization */
    for(int i = 0 ; i < 256 ; i++)
    {
        S[i]=i;
        T[i]= key[i % keyLen];
    }
    /* State Permutation */
    for(int i = 0 ; i < 256; i++)
    {
        j = ( j + S[i] + T[i] ) % 256;
        
         //Swap S[i] & S[j]
        tmp = S[j];
        S[j]= S[i];
        S[i] = tmp;
    }
    j =0; // reintializing j to reuse it
    for(int x = 0 ; x< dataLen ; x++)
    {
        i = (i+1) % 256; // using %256 to avoid exceed the array limit
        j = (j + S[i])% 256; // using %256 to avoid exceed the array limit
        
        //Swap S[i] & S[j]
        tmp = S[j];
        S[j]= S[i];
        S[i] = tmp;
        
        t = (S[i] + S[j]) % 256;

        result[x]= data[x]^S[t]; // XOR generated S[t] with Byte from the plaintext / cipher and append each Encrypted/Decrypted byte to result array
    }
}

    

