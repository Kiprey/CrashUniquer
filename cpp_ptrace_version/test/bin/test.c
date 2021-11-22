#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

void trap_abort() {
    printf("[!] Trapping SIGABORT\n");
    abort();
}

void trap_read_SIGSEV() {
    printf("[!] Trapping read SIGSEV\n");
    int* ptr = NULL;
    printf("%d", *ptr);
}

void trap_write_SIGSEV() {
    printf("[!] Trapping write SIGSEV\n");
    int* ptr = (int*)0xfdfdfdfd;
    *ptr = 0xfd;
}

void trap_buffer_overflow() {
    printf("[!] Trapping buffer overflow read\n");
    int* a = malloc(10);
    printf("[-] read from buffer: %d\n", a[16]);
}

void trap(char ch) {
    switch(ch) {
        case 'a':  trap_abort();            break;
        case 'b':  trap_read_SIGSEV();      break;
        case 'c':  trap_write_SIGSEV();     break;
        case 'd':  trap_buffer_overflow();  break;
        default:   printf("[!] NO trap\n"); break;
    }
}

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
    trap(ch);
    
    printf("[+] Program exit normally\n");
    close(in_fd);

    return 0;
}