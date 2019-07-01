#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <stdarg.h>
#include "aes.h"
#include "hash.h"
#include <errno.h>
#include "fw_head.h"

long FileSize(FILE *f)
{
    long cur, len;
    cur = ftell(f);
    fseek(f, 0L, SEEK_END);
    len = ftell(f);
    fseek(f, cur, SEEK_SET);
    return len;
}

int Decode(char *in, char *out, char *key)
{
    struct fw_header *fw_hdr;
    FILE *infp, *outfp;
    int ret;
    fw_hdr = malloc(sizeof(struct fw_header));
    infp = fopen(in, "rb");
    if(!infp){
        perror("open input file error");
        return -1;
    } 

    ret = fread(fw_hdr, 1, sizeof(struct fw_header), infp);
    outfp = fopen(out, "wb");
    aesDecryptFile(infp, outfp,key);
    fflush(outfp);
    fclose(infp);
    fclose(outfp);
    return 0; 
}

int Encode(char *in, char *out, char *key)
{
    struct fw_header *fw_hdr;
    FILE *infp,*outfp;
    size_t ret;
    void *fbuf;

    fw_hdr = malloc(sizeof(struct fw_header));
    fw_hdr->ver = 'a';
    
    infp = fopen(in, "rb");
    if(!infp){
        perror("open input file error");
        return -1;
    }

    fw_hdr->size = FileSize(infp);
    sprintf(fw_hdr->hash,"%s", sha256_hash(infp));
    fw_hdr->start = sizeof(struct fw_header);

    outfp = fopen(out, "wb");
    if(!outfp){
        perror("open output file error");
        return -1;
    }
 
    fwrite(fw_hdr, sizeof(struct fw_header), 1, outfp);
    fflush(outfp);
    aesEncryptFile(infp, outfp, key);

    fflush(outfp);
    fclose(outfp);
    fclose(infp);
    free(fw_hdr);
    return 0;
}

int main(int argc, char *argv[])
{
    int ret;
    int i;
    char code;
    long fsize;
    char key[256];

    while((ret = getopt(argc, argv, "::d::e::k:")) != -1)
    {
        switch(ret) {
            case 'd':
                if(!code)
                    code =  ret;
                else
                    return -1;

                break;
            case 'e':
                if(!code)
                    code = ret;
                else
                    return -1;                
        
                break;
            case 'k':
                sprintf(key, "%s",optarg);
                break;
            case '?':
                break;
            case ':':
                break;
            default:
                break;
        }
    }

    switch(code){
        case  'd':
            Decode(argv[4], argv[5], key);
            break;
        case  'e':
            Encode(argv[4], argv[5], key);
            break;
    }
    
	return 0;
}
