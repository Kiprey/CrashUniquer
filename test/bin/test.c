#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(int argc, char**argv) {
    int in_fd = -1;
    if(argc < 2) {
        printf("[+] Using stdin\n");
        in_fd = dup(0);
    }
    else {
        printf("[+] Using file(%s)\n", argv[1]);
        in_fd = open(argv[1], O_RDONLY);
    }
    char ch;
    if(read(in_fd, &ch, 1) < 1) {
        perror("read");
        exit(1);
    }
    switch(ch) {
        case 'a': 
            printf("[!] Trapping SIGABORT\n");
            abort();
            break;
        case 'b': {
            printf("[!] Trapping read SIGSEV\n");
            int* ptr = NULL;
            printf("%d", *ptr);
        }
        case 'c': {
            printf("[!] Trapping write SIGSEV\n");
            int* ptr = (int*)0xfdfdfdfd;
            *ptr = 0xfd;
        }
        case 'd': {
            printf("[!] Trapping buffer overflow read\n");
            int* a = malloc(10);
            printf("[-] read from buffer: %d\n", a[16]);
            break;
        }
        default:
            printf("[!] NO trap\n");
            break;
    }
    printf("[+] Program exit normally\n");
    close(in_fd);

    return 0;
}