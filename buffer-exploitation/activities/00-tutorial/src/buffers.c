#include <stdio.h>
#include <stdlib.h>

char g_buf_init_zero[32] = {0};
/* g_buf_init_vals[5..31] will be 0 */
char g_buf_init_vals[32] = {1, 2, 3, 4, 5};
const char g_buf_const[32] = "Hello, world\n";

int main(void)
{
    char l_buf[32];
    static char s_l_buf[32];
    char *heap_buf = malloc(32);

    free(heap_buf);

    return 0;
}
