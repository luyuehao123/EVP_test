/*
 * @Author: Lu, Yuehao
 * @Date: 2026-06-29 22:08:53
 * @Last Modified by: Lu, Yuehao
 * @Last Modified time: 2026-06-29 22:08:53
 * @Description: test for symmetric encrypt
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define BUF_SIZE 1024


static const char* finput = "plaintext";
static const char* foutput = "ciphertext";
static const unsigned char key[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};

int do_crypt(FILE* in,FILE* out,int do_encrypt);

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    int ret = EXIT_FAILURE;
    FILE* fin = fopen(finput,"r");
    FILE* fout = fopen(foutput,"w+");
    FILE* ffin = NULL;
    FILE* ffout = NULL;

    if(fin == NULL || fout == NULL)
    {
        perror("file open failed");
        goto cleanup;
    }
    if(do_crypt(fin,fout,1) != 0) // encrypt
    {
        fprintf(stderr, "encryption failed.\n");
        goto cleanup;
    }
    fclose(fin);
    fin = NULL;
    fclose(fout);
    fout = NULL;

    ffin = fopen(foutput,"r");
    ffout = fopen("decrypted_plaintext","w+");
    if(ffin == NULL || ffout == NULL)
    {
        perror("file open failed");
        goto cleanup;
    }
    if(do_crypt(ffin,ffout,0) != 0) // decrypt
    {
        fprintf(stderr, "decryption failed.\n");
        goto cleanup;
    }

    ret = EXIT_SUCCESS;

cleanup:
    if (fin) {
        fclose(fin);
    }
    if (fout) {
        fclose(fout);
    }
    if (ffin) {
        fclose(ffin);
    }
    if (ffout) {
        fclose(ffout);
    }

    return ret;
}

int do_crypt(FILE* in,FILE* out,int do_encrypt)
{
    unsigned char inbuf[BUF_SIZE];
    unsigned char outbuf[BUF_SIZE + EVP_MAX_BLOCK_LENGTH];
    int ret = 1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    if(!EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, NULL, do_encrypt)) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    for (;;) {
        size_t inlen = fread(inbuf,1,BUF_SIZE,in);
        if(inlen == 0) {
            if (ferror(in)) {
                perror("fread");
                goto cleanup;
            }
            break;
        }
        
        int outlen = 0;
        if(!EVP_CipherUpdate(ctx,outbuf, &outlen,inbuf,(int)inlen)) {
            ERR_print_errors_fp(stderr);
            goto cleanup;
        }
        if(fwrite(outbuf, 1, outlen, out) != (size_t)outlen) {
            perror("fwrite");
            goto cleanup;
        }
    }
    
    int outlen = 0;
    if(!EVP_CipherFinal_ex(ctx, outbuf, &outlen)) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    if(fwrite(outbuf, 1, outlen, out) != (size_t)outlen) {
        perror("fwrite");
        goto cleanup;
    }

    ret = 0;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}
    
