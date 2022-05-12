#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX 10

void secret()
{
    printf("Secret is SECRET\n");
}

void vulnerable(char* str)
{
    char msg[MAX];
    strcpy(msg, str);
}

int main(int argc, char **argv)
{
  

    if (argc != 2) {
        printf("USAGE: %s <msg>\n", argv[0]);
        exit(1);
    }

    vulnerable(argv[1]);

    printf("Echoed message: %s\n", argv[1]);
    return 0;
}