#ifndef CS457_CRYPTO_H
#define CS457_CRYPTO_H
#include <stdio.h>
void* one_time_pad_encr(void* plaintext,size_t size,void* key);
void* one_time_pad_decr(void* ciphertext,size_t size,void* key);
char* affine_encr(char* plaintext);
char* affine_decr(char* ciphertext);
char* decryptor(char* ciphertext,char* filename);
char* trithemius_encr(char* plaintext);
char* trithemius_decr(char* ciphertext);
char*  scytale_encr(char* plaintext,int diameter);
char*  scytale_decr(char* ciphertext,int diameter);
char* rail_fence_encr(char* plaintext,int rails);
char* rail_fence_decr(char* ciphertext);
#endif