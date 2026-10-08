#include <stdio.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    if (puts(argv[1]) < 0 || fflush(stdout) != 0) return 3;
    usleep(200000);
    return 0;
}
