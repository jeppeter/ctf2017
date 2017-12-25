#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    void *buf0, *buf1, *buf2;
    buf0 = malloc(0x30);
    buf1 = malloc(0x30);
    buf2 = malloc(0x30);

    printf("buf0 [%p] buf1 [%p] buf2[%p]\n",buf0,buf1,buf2);

    free(buf2);
    free(buf1);
    free(buf0);



    return 0;
}