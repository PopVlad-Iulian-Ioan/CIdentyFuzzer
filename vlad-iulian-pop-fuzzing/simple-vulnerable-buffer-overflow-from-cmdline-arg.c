#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX 10

void secret()
{
    printf("Secret is SECRET\n");
}


int main(int argc, char **argv)
{
    char msg[MAX];

    if (argc != 2) {
        printf("USAGE: %s <msg>\n", argv[0]);
        exit(1);
    }

    strcpy(msg, argv[1]);

    printf("Echoed message: %s\n", msg);

    return 0;
}