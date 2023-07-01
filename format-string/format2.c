#include <stdio.h>
#include <string.h>

#define MAX_STRING 1000
int main(int argc, char **argv)
{
        char msg[MAX_STRING];
        if (argc != 2) {
                printf("Usage error: %s mesg\n", argv[0]);
                return 1;
        }
        snprintf(msg, MAX_STRING, "Message: %s.\n", argv[1]);
        printf(msg);
        return 0;
}