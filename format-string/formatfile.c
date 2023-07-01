#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define MAX 300

#define BIGA 100

#define dump_stack(frame_no)   \
    { \
        register void* stack_pointer asm("esp");    \
        printf("esp = %p\n", stack_pointer);        \
        for (int i = 0; i < frame_no; i++) {               \
            printf("%p: 0x%08x\n", (int*)stack_pointer + i, *((int*)stack_pointer + i));    \
        }                                           \
        void *ret_addr = __builtin_extract_return_addr (__builtin_return_address (0)); \
        printf("ret_addr: %p\n", ret_addr); \
    }

int sum(int a, int b, int c)
{
    for(int i=0;i<5;i++)
        a=a+b+c;

    return a;
}
void secret()
{
    printf("Secret is SECRET\n");
}


int dif(int a,int b, int c)
{
    if(a<20)
    a=b-c;
    else
    a=c-b;
    return a;
}

void vuln_funct(char *file_name)
{
    char msg[MAX];
    int fd;
    int msg_len;
    unsigned int read_bytes;

    char biga[BIGA];
    for(int i=0;i<BIGA;i++)
    biga[0]='B';

    printf("&msg[0]     = %p\n", &msg[0]);                
    printf("&fd         = %p\n", &fd);                  
    printf("&msg_len    = %p\n", &msg_len);        
    printf("&read_bytes = %p\n", &read_bytes);  
    printf("&secret     = %p\n", &secret);

    //dump_stack(24);

    

    fd = open(file_name, O_RDONLY);
    if (fd < 0) {
        perror("Cannot open file");
        exit(2);
    }

    // dump_stack(16);


    if (read(fd, &msg_len, sizeof(msg_len)) != sizeof(msg_len)) {
        perror("Cannot read msg len from file");
        exit(3);
    }

    // dump_stack(16);

    if ((read_bytes = read(fd, msg, msg_len)) < 0) {
        perror("Cannot read msg from file");
        exit(4);
    }

     dump_stack(20); 

    printf(msg); 

    int a=0,b=1,c=2;
    a=sum(a,b,c);
    printf("\na este egal cu %d\n",a);
}

int main(int argc, char **argv)
{
    
    if (argc != 2) {
        printf("USAGE: %s <msg>\n", argv[0]);
        exit(1);
    }

    int a=0,b=1,c=2;
    a=sum(a,b,c);
    vuln_funct(argv[1]);
    a=sum(a,b,c);
    a=dif(a,b,c);
    if (a>BIGA)
    a=a-BIGA;
    else
    a=BIGA-a;

    printf("\nDupa call-uri\n");
}