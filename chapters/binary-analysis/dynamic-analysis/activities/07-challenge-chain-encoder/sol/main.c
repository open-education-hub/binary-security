    /***********************************************************
    * Base64 example app                                       *
    * @author Ahmed Elzoughby                                  *
    * @date July 23, 2017                                      *
    * Purpose: Demonstration of Base64 library                 *
    * Usage: base64 (encode | decode) <source> [<destination>] *
    ***********************************************************/

#include <stdio.h>
#include <stdbool.h>
#include "base64.h"
#include <stdint.h>
#include "md5.h"
#include <unistd.h>
//password 
//admin123 



void password_accepted()
{
	execve("/bin/sh", 0, 0);
}
void print_hash(uint8_t *p){
	for(unsigned int i = 0; i < 16; ++i){
		printf("%02x", p[i]);
	}
	printf("\n");
}




int main(int argc, char* argv[]) {
    char input[100],input2[100],*output,*output2;
    uint8_t pass1[]={0x0b,0x8b,0x94,0x64,0x32,0xf1,0xac,0x91,0xf0,0xb0,0x7b,0xd5,0xf8,0xdf,0x65,0x87},ok=1;
    uint8_t pass2[]={0x7d,0x6c,0xa0,0xe4,0x76,0x76,0xcc,0x0b,0x93,0x4d,0x06,0x40,0x2a,0x56,0xe2,0xc0};
    scanf("%16s",input);
    scanf("%16s",input2);
    output=base64_encode(input);
    output2=base64_encode(input2);
    uint8_t *p = md5String(output),*q = md5String(output2);
    
    for(int i=0;i<16;i++)
    {
     if ( pass1[i] != p[i] || pass2[i]!=q[i] )
     	ok=0;
     	break;
    }
    if (ok==1)
    	password_accepted();    

}




