#include <unistd.h>

char buf[0x200];

static void helper(void)
{
    asm volatile("pop %rdx");
    asm volatile("ret");
}

static void read_input(void)
{
    char buf[32];
    ssize_t out = read(0, buf, 0x38 + + 0x48);
}

int main(void)
{
    char dummy[0x200];
    read_input();
    write(1, "WIN\n", 4);
    return 0;
}
