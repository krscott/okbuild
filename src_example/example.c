#include <stdio.h>

int main(int argc, char *argv[]) {
    if (argc == 1) {
        printf("Hello, World!\nGive me some arguments!\n");
    } else {
        for (int i = 1; i < argc; ++i) {
            printf("%s\n", argv[i]);
        }
    }

    return 0;
}
