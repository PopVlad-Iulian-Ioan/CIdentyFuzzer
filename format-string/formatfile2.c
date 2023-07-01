#include <stdio.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#define MAX_STRING 1000
int main(int argc, char **argv)
{
    char msg[MAX_STRING];
        if (argc != 2) {
                printf("Usage error: %s mesg\n", argv[0]);
                return 1;
        }
    FILE* file = fopen(argv[1],  "rb");

    if (file == NULL) {
        printf("Error opening the file.\n");
        return 1;
    }
    fgets(msg, sizeof(msg), file);
    char output[MAX_STRING];
    snprintf(output, MAX_STRING, "Message: %s.\n", msg);
    printf(output);

    fclose(file);
    return 0;
}