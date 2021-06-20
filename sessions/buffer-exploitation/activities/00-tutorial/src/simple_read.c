#include <stdio.h>

int main(void) {
    char buf[128];
    fread(buf, 1, 256, stdin);
    return 0;
}
