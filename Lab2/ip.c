#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_SIZE 16

int check_ip(const char *ip) {
    int dots = 0;
    for (int i = 0; ip[i]; i++) {
        if (ip[i] == '.')
            dots++;
        else if (!isdigit(ip[i]))
            return 0;
    }
    return dots == 3;
}

int main(int argc, char *argv[]) {
    char buffer[MAX_SIZE] = {0};

    if (argc != 2) {
        printf("Usage: %s <IP>\n", argv[0]);
        return 1;
    }

    if (check_ip(argv[1])) {
        strcpy(buffer, argv[1]);                        /* FLAW */
        printf("Valid IP: %s\n", buffer);
    } else {
        printf("Invalid IP\n");
    }

    return 0;
}
