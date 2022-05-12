#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define MAX 10

void secret()
{
    printf("Secret is SECRET\n");
}


int main(int argc, char **argv)
{
    char msg[MAX];
    int fd;
    int msg_len;
    unsigned int read_bytes;

    if (argc != 2) {
        printf("USAGE: %s <msg>\n", argv[0]);
        exit(1);
    }

    fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        perror("Cannot open file");
        exit(2);
    }

    if (read(fd, &msg_len, sizeof(msg_len)) != sizeof(msg_len)) {
        perror("Cannot read msg len from file");
        exit(3);
    }

    if ((read_bytes = read(fd, msg, msg_len)) < 0) {
        perror("Cannot read msg from file");
        exit(4);
    }

    msg[read_bytes] = '\0';

    secret();

    printf("Echoed message: %s\n", msg);

    return 0;
}