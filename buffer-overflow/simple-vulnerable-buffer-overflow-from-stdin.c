#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define MAX 10

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

void secret()
{
    printf("Secret is SECRET\n");
}


void vuln_funct()
{
    char msg[MAX];
    
    gets(msg);

    printf("Echoed message: %s\n", msg);

}

int main(int argc, char **argv)
{
    
    if (argc != 2) {
        printf("USAGE: %s <msg>\n", argv[0]);
        exit(1);
    }

    vuln_funct();
    
    return 0;
}