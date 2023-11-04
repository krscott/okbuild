/**
 * @file example.c
 * @author your name (you@domain.com)
 * @brief Example program built with okbuild
 * @version 0.1
 * @date 2023-11-04
 *
 * @copyright Copyright (c) 2023
 *
 */

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
