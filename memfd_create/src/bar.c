/*
compile and deploit it on a HTTP server: 
gcc bar.c bar

*/

#include <stdio.h>

int main() {
    FILE *fptr;

    fptr = fopen("/tmp/woot.txt", "w+");
    if (!fptr) {
        printf("Something went wrong");
    }
    fprintf(fptr, "%s", "hello from memory");
    fclose(fptr);

    return 0;
}