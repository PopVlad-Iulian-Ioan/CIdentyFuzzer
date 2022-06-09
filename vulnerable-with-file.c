#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#define MAX 10

void secret()
{
    printf("Secret is SECRET\n");
}


int main(int argc, char **argv)
{
    char msg[MAX];
    int fd;
    char msg_len;
    int len=0;
    int read_bytes;

    if (argc != 2) {
        printf("USAGE: %s <msg>\n", argv[0]);
        exit(1);
    }

    fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        perror("Cannot open file");
        exit(2);
    }
     read(fd,&msg_len ,1);
    while(isdigit(msg_len))
    {
        len=len*10+ msg_len-48;
        read(fd,&msg_len , 1);
    }

    read_bytes = read(fd, msg, len);
    if (read_bytes < 0) {
        perror("Cannot read msg from file");
        exit(3);
    }
    msg[read_bytes] = '\0';

    //secret();

    printf("Echoed message: %s\n", msg);

    return 0;
}