#ifndef FW_HEAD_H
#define FW_HEAD_H
#include <stdio.h>
#include <stdint.h>

struct fw_header {
    char ver;
    char arch[8];
    char hash[256];
    long size;
    int start;
};

long FileSize(FILE *f);
int Decode(char *in, char *out, char *key);
int Encode(char *in, char *out, char *key);

#endif
