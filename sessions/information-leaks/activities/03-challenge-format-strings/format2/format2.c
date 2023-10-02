#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void vuln()
{
    char buffer[512];

    fgets(buffer, sizeof(buffer), stdin);
    printf(buffer);
  
  if(target == 64) {
    printf("GTAB value is correct :)\n");
  } else {
    printf("GTAB value not good %d :(\n", target);
  }
}

int main(int argc, char **argv)
{
  vuln();
}
