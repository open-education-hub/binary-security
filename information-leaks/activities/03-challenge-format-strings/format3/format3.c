#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void printbuffer(char *string)
{
  printf(string);
}

void vuln()
{
  char buffer[512];

  fgets(buffer, sizeof(buffer), stdin);

  printbuffer(buffer);
  
  if(target == 0x01025544) {
    printf("You're getting closer to finding out what GTAB means :)\n");
  } else {
    printf("Close but not really, your value is %08x :(\n", target);
  }
}

int main(int argc, char **argv)
{
  vuln();
}
