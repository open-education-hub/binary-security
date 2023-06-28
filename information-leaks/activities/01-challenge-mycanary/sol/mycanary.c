#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

unsigned int good_canary;

unsigned int canary_init() {
    unsigned char r;
    int rfd = open("/dev/random", O_RDONLY);
    good_canary = 0xDEADBEEF;
    good_canary &= ~0x00FF0000;
    read(rfd, &r, 1);
    r=(char)(r/16);
    good_canary = good_canary | (r << 16);
    return good_canary;
}

void canary_check(unsigned int current) {
    if (current != good_canary) {
        printf("Stack smaching detected: %p vs. %p\n",
               (void*)current, (void*)good_canary);
        exit(1);
    }
    printf("Canary OK!\n");
}

void bad_func() {
    printf("Missile launched! your flag is SSS_{stop launching them}\n");
    printf("the end\n");
    scanf("%d",good_canary);
}

void func() {
    unsigned int canary = canary_init();
    char name[100];
    gets(name);
    canary_check(canary);
}

int main() {
    setvbuf(stdout, NULL, _IOLBF, 0);
    func();
    return 0;
}
