#include "cs457_crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#define MAX 100000
#define PLAINTEXT "ThisIsACat"
#define P_SIZE 10
#define RANDOM_KEY_SIZE P_SIZE
#define  AFFINE_PLAINTEXT TRITHEMIUS_PLAINTEXT
#define  TRITHEMIUS_PLAINTEXT "It is a transposition cipher that involves a cylinder with a strip of \
parchment wound around it, containing the written message."
#define SCYTALE_PLAINTEXT "I am hurt very badly help . PLS!! ComEEEEE@@"
#define RAIL_FENCE_PLAINTEXT  "We are discovered! Run At ONCE."
#define DIAMETER 10


int x;

int main() {
    char plaintext[MAX] = PLAINTEXT;
    char key[] = "randombyte";
    char random[RANDOM_KEY_SIZE];
    int fd = open("/dev/urandom", O_RDONLY);
    read(fd, random, RANDOM_KEY_SIZE);
    close(fd);
    printf("Random key in Hex: ( ");
    for (int i = 0; i < RANDOM_KEY_SIZE; i++) {
        printf("%02x ", (unsigned char)random[i]);
    }
    printf(")\n");
    char* ciphertext = (char*)one_time_pad_encr(plaintext, P_SIZE+1, random);
    char* decrypted = (char*)one_time_pad_decr(ciphertext, P_SIZE+1, random);
    printf("1.One-Time-Pad\n");
    printf("\tPlaintext: %s\n", plaintext);

    printf("\tCiphertext: ");
    for (int i = 0; i < 10; i++) {
        printf("%02x ", (unsigned char)ciphertext[i]);
    }
    printf("\n");
    printf("\tDecrypted: %s\n", decrypted);
    free(ciphertext);
    free(decrypted);

    //affine
    printf("2.Affine Cipher\n");
    strcpy(plaintext, AFFINE_PLAINTEXT);
    char* affine_ciphertext = affine_encr(plaintext);
    char* affine_decrypted = affine_decr(affine_ciphertext);
    printf("\tPlaintext: %s\n", plaintext);
    printf("\tCiphertext: %s\n", affine_ciphertext);
    printf("\tDecrypted: %s\n", affine_decrypted);
    free(affine_ciphertext);
    free(affine_decrypted);

    //decryptor
    printf("3.Decryptor\n");

    printf("\tGive filename to decrypt: ");

    char filename[100];
    scanf("%s", filename);
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        printf("Error: File not found\n");
        return 1;
    }
    fseek(file, 0, SEEK_END);
    long fsize = ftell(file);
    fseek(file, 0, SEEK_SET);
    char* file_text = malloc(fsize + 1);
    fread(file_text, 1, fsize, file);
    fclose(file);
    file_text[fsize] = 0;
    printf("\nFile text:\n%s\n\n", file_text);
    file_text=decryptor(file_text,filename);

    free(file_text);
    //trithemius
    printf("4.Trithemius Cipher\n");
    strcpy(plaintext, TRITHEMIUS_PLAINTEXT);
    char* trithemius_ciphertext = trithemius_encr(TRITHEMIUS_PLAINTEXT);
    char* trithemius_decrypted = trithemius_decr(trithemius_ciphertext);
    printf("\tPlaintext: %s\n", plaintext);
    printf("\tCiphertext: %s\n", trithemius_ciphertext);
    printf("\tDecrypted: %s\n", trithemius_decrypted);
    free(trithemius_ciphertext);
    free(trithemius_decrypted);

    //scytale
    printf("5.Scytale Cipher\n");
    strcpy(plaintext, SCYTALE_PLAINTEXT);
    char* scytale_ciphertext = scytale_encr(SCYTALE_PLAINTEXT, DIAMETER);
    char* scytale_decrypted = scytale_decr(scytale_ciphertext, DIAMETER);
    printf("\tPlaintext: %s\n", plaintext);
    printf("\tCiphertext: %s\n", scytale_ciphertext);
    printf("\tDecrypted: %s\n", scytale_decrypted);
    free(scytale_ciphertext);
    free(scytale_decrypted);

    strcpy(plaintext,RAIL_FENCE_PLAINTEXT);
    char* rail_fence_ciphertext = rail_fence_encr(plaintext, 3);
    char* rail_fence_decrypted = rail_fence_decr(rail_fence_ciphertext);

    printf("6.Rail Fence Cipher\n");
    printf("\tPlaintext: %s\n", plaintext);
    printf("\tCiphertext: %s\n", rail_fence_ciphertext);
    printf("\tDecrypted: %s\n", rail_fence_decrypted);
    free(rail_fence_ciphertext);
    free(rail_fence_decrypted);
    

    return 0;
}
