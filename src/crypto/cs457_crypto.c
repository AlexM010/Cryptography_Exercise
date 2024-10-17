#include "cs457_crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define MAX 100000
#define DICTIONARY "testfiles/words.txt"

void* one_time_pad_encr(void* plaintext, size_t size, void* key) {
    char* ciphertext = (char*)malloc(size);
    for (int i = 0; i < size; i++) {
        ciphertext[i] = ((char*)plaintext)[i] ^ ((char*)key)[i];
    }
    return ciphertext;
}
void* one_time_pad_decr(void* ciphertext, size_t size, void* key) {
    char* plaintext = (char*)malloc(size);
    for (int i = 0; i < size; i++) {
        plaintext[i] = ((char*)ciphertext)[i] ^ ((char*)key)[i];
    }
    return plaintext;
}

char* affine_encr(char* plaintext) {
    char* ciphertext = (char*)malloc(strlen(plaintext)+1);
    for (int i = 0; i < strlen(plaintext); i++) {
        if (plaintext[i] >= 'a' && plaintext[i] <= 'z') {
            ciphertext[i] = (5 * (plaintext[i] - 'a') + 8) % 26 + 'a';
        } else if (plaintext[i] >= 'A' && plaintext[i] <= 'Z') {
            ciphertext[i] = (5 * (plaintext[i] - 'A') + 8) % 26 + 'A';
        } else {
            ciphertext[i] = plaintext[i];
        }
    }
    ciphertext[strlen(plaintext)] = '\0';
    return ciphertext;
}
char* affine_decr(char* ciphertext) {
    char* plaintext = (char*)malloc(strlen(ciphertext)+1);
    for (int i = 0; i < strlen(ciphertext); i++) {
        if (ciphertext[i] >= 'a' && ciphertext[i] <= 'z') {
            plaintext[i] = (21 * (ciphertext[i] - 'a' - 8)+21*26) % 26 + 'a';
        } else if (ciphertext[i] >= 'A' && ciphertext[i] <= 'Z') {
            plaintext[i] = (21 * (ciphertext[i] - 'A' - 8)+21*26) % 26 + 'A';
        } else {
            plaintext[i] = ciphertext[i];
        }
    }
    plaintext[strlen(ciphertext)] = '\0';
    return plaintext;
}
static float res[26][3];
static void letter_freq(char * filename){
    FILE *file = fopen(filename,"r");
    if(file==NULL){
        printf("Error: File not found\n");
        return;
    }
    int c;
    int freq[26]={0};
    int total=0;
    while((c=fgetc(file))!=EOF){
        if(c>='A' && c<='Z'){
            freq[c-'A']++;
            total++;
        }
        if(c>='a' && c<='z'){
            freq[c-'a']++;
            total++;
        }
    }

    for(int i=0;i<26;i++){
        res[i][0]=freq[i];
        res[i][1]=(float)freq[i]/total;
        res[i][2]=i;
    }
    fclose(file);

    for(int i=0;i<26;i++){
        for(int j=i+1;j<26;j++){
            if(res[i][0]<res[j][0]){
                float temp=res[i][0];
                res[i][0]=res[j][0];
                res[j][0]=temp;
                temp=res[i][1];
                res[i][1]=res[j][1];
                res[j][1]=temp;
                temp=res[i][2];
                res[i][2]=res[j][2];
                res[j][2]=temp;
            }
        }
    }
    printf("Letter frequencies:\n");
    for(int i=0;i<26;i++){
        printf("%c: %.2f %%\t",(int)res[i][2]+'A',res[i][1]*100);
    }
    printf("\n");
    return;
}
char* matching_words(char* word,char*filename){
    char* suggestion=malloc(100000);

    int len=strlen(word);
    FILE *file = fopen(filename,"r");
    if(file==NULL){
        printf("Error: File not found\n");
        return NULL;
    }
    char temp[100];
    int max=0;
    while(fscanf(file,"%s",temp)!=EOF){
        int score=0;
        if(strlen(temp)!=len){
            continue;
        }
        for(int i=0;i<len;i++){
            if(word[i]!='*'&&temp[i]!=word[i] && temp[i]!=word[i]+32){
                score=0;
                break;
            }

            if(temp[i]==word[i] || temp[i]==word[i]+32){
                score++;
            }
        }
        if(score>max){
            max=score;
        }
    }
    fseek(file,0,SEEK_SET);
    strcpy(suggestion,"");
    while(fscanf(file,"%s",temp)!=EOF){
        int score=0;
        if(strlen(temp)!=len){
            continue;
        }
        for(int i=0;i<len;i++){
            if(word[i]!='*'&&temp[i]!=word[i] && temp[i]!=word[i]+32){
                score=0;
                break;
            }
            if(temp[i]==word[i] || temp[i]==word[i]+32){
                score++;
            }
        }
        if(score==max){
            strcat(suggestion,"\t");
            strcat(suggestion,temp);
        }
    }
    fclose(file);

    return suggestion;
}

char* decryptor(char* ciphertext, char* ciphertext_file){
    int len=strlen(ciphertext);
    char* partially_decrypted= (char*)malloc(len+1);
    char map[27];
    char new_map[27];
    char m,n_m;
    char* suggestion;
    int c=0;
    strcpy(map,"ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    strcpy(new_map,"**************************");
    partially_decrypted[len]='\0';
    for (int i = 0; i < strlen(ciphertext); i++) {
        if (ciphertext[i] >= 'a' && ciphertext[i] <= 'z') {
            ciphertext[i] = ciphertext[i] - 32;
        }
    }
    printf("English ");
    letter_freq(DICTIONARY);
    printf("Ciphertext ");
    letter_freq(ciphertext_file);
    getchar();
    while(c!=EOF){
        printf("Next mapping: ");
        m=getchar();
        if(m<'A' || m>'Z'){
            printf("Invalid input\n");
            getchar();
            continue;
        }

        printf("%c -> ",m);
        getchar();
        n_m=getchar();

        if(n_m<'A' || n_m>'Z'){
            printf("Invalid input\n");
            getchar();
            continue;
        }

        new_map[m-'A']=n_m;
        for(int i=0;i<len;i++){
            if(ciphertext[i]>='A' && ciphertext[i]<='Z'){
                partially_decrypted[i]=new_map[ciphertext[i]-'A'];
            }else{
                partially_decrypted[i]=ciphertext[i];
            }
        }
        printf("Partially decrypted text:\n\n%s\n",partially_decrypted);

        printf("Enter partially decrypted word:");
        char word[100];
        scanf("%s",word);
        suggestion=matching_words(word,DICTIONARY);
        printf("Suggestion: %s\n",suggestion);
        free(suggestion);


        printf("\nPress any key to continue or Ctrl-D to stop\n");
        getchar();
        c=getchar();
    }
    free(partially_decrypted);

    return ciphertext;
}



char* trithemius_encr(char* plaintext){
    char* ciphertext= (char*)malloc(strlen(plaintext)+1);
    int i,j=0;

    for (i = 0;i<strlen(plaintext); i++) {
        if (plaintext[i] >= 'a' && plaintext[i] <= 'z') {
            ciphertext[i]=(plaintext[i] - 'a' + j) % 26 + 'a';
            j++;
        }else if (plaintext[i] >= 'A' && plaintext[i] <= 'Z') {
            ciphertext[i]=(plaintext[i] - 'A' + j) % 26 + 'A';
            j++;
        }else {
            ciphertext[i]=plaintext[i];
        }
    }
    ciphertext[i]='\0';
    return ciphertext;
}
char* trithemius_decr(char* ciphertext){
    char* plaintext =(char*)malloc(strlen(ciphertext)+1);
    int i,j=0;
    for (i=0; i<strlen(ciphertext); i++) {
        if(ciphertext[i] >= 'a' && ciphertext[i] <= 'z') {
            plaintext[i]=(ciphertext[i] - 'a' - j + 26*(j/26+1)) % 26 + 'a';
            j++;
        }else if (ciphertext[i] >= 'A' && ciphertext[i] <= 'Z') {
            plaintext[i]=(ciphertext[i] - 'A' - j + 26*(j/26+1)) % 26 + 'A';
            j++;
        }else {
            plaintext[i]=ciphertext[i];
        }
    }
    plaintext[i]='\0';
    return plaintext;
}

char scytale[MAX];
char rail_fence[MAX];
void ommit(char* plaintext,int how){
    if(how==5){
        strcpy(scytale,plaintext);
    }else if(how==6){
        strcpy(rail_fence,plaintext);
    }

}
void* add_ommited(char* plaintext,int how){
    char* new_plaintext;
    int j=0;
    int k=0;
    if(how==5){
        new_plaintext=(char*)malloc(strlen(plaintext)+strlen(scytale)+1);
        for(int i=0;i<strlen(scytale);i++){
            if((scytale[i]>='A' && scytale[i]<='Z') || (scytale[i]>='a' && scytale[i]<='z')){
                new_plaintext[j]=plaintext[k];
                k++;
                j++;
            }else{
                new_plaintext[j]=scytale[j];
                j++;
            }
        }
    }else if(how==6){
        new_plaintext=(char*)malloc(strlen(plaintext)+strlen(rail_fence)+1);
        for(int i=0;i<strlen(rail_fence);i++){
            if((rail_fence[i]>='A' && rail_fence[i]<='Z') || (rail_fence[i]>='a' && rail_fence[i]<='z')){
                new_plaintext[j]=plaintext[k];
                k++;
                j++;
            }else{
                new_plaintext[j]=rail_fence[j];
                j++;
            }
        }
    }else{
        return NULL;
    }
    new_plaintext[j]='\0';
    return new_plaintext;
}

char*  scytale_encr(char* plaintext,int diameter){
    int len=0;
    char* new_plaintext=(char*)malloc(strlen(plaintext)+1+diameter);
    ommit(plaintext,5);
    for(int i = 0 ; i < strlen(plaintext); i++ ){
        if((plaintext[i]>='A' && plaintext[i]<='Z')||(plaintext[i]>='a' && plaintext[i]<='z')){
            new_plaintext[len]=plaintext[i];
            len++;
        }
    }
    int rows=len/diameter;
    if(len%diameter!=0){
        rows++;
        for(int i=len;i<rows*diameter;i++){
            new_plaintext[i]=' ';
            len++;
        }

    }
    new_plaintext[len]='\0';
    char* ciphertext=(char*)malloc(strlen(plaintext)+diameter+1);
    int k=0,j=0;
    for(k=0;k<strlen(new_plaintext);k++){
            ciphertext[k]=new_plaintext[((j%rows)*diameter + (j/rows))];
            j++;
    }
    ciphertext[k]='\0';
    free(new_plaintext);
    return ciphertext;
}
char*  scytale_decr(char* ciphertext,int diameter){
    int len=0;
    char* new_ciphertext=(char*)malloc(strlen(ciphertext)+1);

    for(int i = 0 ; i < strlen(ciphertext); i++ ){
        if((ciphertext[i]>='A' && ciphertext[i]<='Z')||(ciphertext[i]>='a' && ciphertext[i]<='z')||ciphertext[i]==' '){
            new_ciphertext[len]=ciphertext[i];
            len++;
        }
    }
    int rows=len/diameter;
    if(len%diameter!=0){
        rows++;
        for(int i=len;i<rows*diameter;i++){
            new_ciphertext[i]=' ';
            len++;
        }
    }
    char* plaintext=(char*)malloc(strlen(ciphertext)+1);
    int k=0,j=0;
    for(k=0;k<strlen(new_ciphertext);k++){
        plaintext[k]=new_ciphertext[(j%diameter)*rows + (j/diameter)];
        j++;
    }
    plaintext[k]='\0';
    free(new_ciphertext);
    char *temp=add_ommited(plaintext,5);
    free(plaintext);
    return temp;
}

char* rail_fence_encr(char* plaintext,int rails){
    int n=strlen(plaintext);
    char** rail = malloc( sizeof(char*) * rails );
    char* ciphertext = malloc( n + rails +1 );
    ommit(plaintext,6);
    //remove spaces and punctuations
    char* new_plaintext=(char*)malloc(n+1);
    int len=0;
    for(int i = 0 ; i < n; i++ ){
        if((plaintext[i]>='A' && plaintext[i]<='Z')||(plaintext[i]>='a' && plaintext[i]<='z')){
            new_plaintext[len]=plaintext[i];
            len++;
        }
    }

    strcpy(ciphertext,"");
    for(int i = 0; i < rails; i++){
        rail[i] = calloc( n,sizeof(char) );
    }
    int i,j,k=0;
    int* railIndex=calloc(rails,sizeof(int));
    for(i = 0; i < rails; i++){
        if(k==n+1){
            break;
        }
        rail[i][railIndex[i]]=new_plaintext[k++];
        railIndex[i]++;
        if(i==rails-1){
            for(j = i-1; j >=0;j--){
                if(k==n){
                    break;
                }
                rail[j][railIndex[j]]=new_plaintext[k++];
                railIndex[j]++;
                if(j==0){
                    i=0;
                }
            }
        }
    }

    for(i=0;i<rails;i++){
        strcat(ciphertext,rail[i]);
        if(i!=rails-1)
            strcat(ciphertext," ");
    }

    for(int i = 0; i < rails; i++){
        free(rail[i]);
    }
    free(rail);
    free(railIndex);
    free(new_plaintext);

    return ciphertext;
}

char* rail_fence_decr(char* ciphertext){
    int n=strlen(ciphertext);
    char* plaintext = malloc( n +1 );
    strcpy(plaintext,"");
    int rails=0;
    for(int i = 0; i < n; i++){
        if(ciphertext[i]==' '){
            rails++;
        }
    }
    rails++;
    char** rail = calloc(rails,sizeof(char*));
    int* railIndex = calloc(rails,sizeof(int) );
    for(int i = 0; i < rails; i++){
        rail[i] = calloc( n,sizeof(char));
        railIndex[i]=0;
    }

    int i=0,j=0,k=0;
    while(i<n){
        if(ciphertext[i]==' '){
            i++;
            j++;
            continue;
        }
        rail[j][railIndex[j]]=ciphertext[i];
        railIndex[j]++;
        i++;
    }
    k=0;

    for(i=0;i<rails;i++){
        railIndex[i]=0;
    }
    for(i = 0; i < rails; i++){
        if(k==n){
            break;
        }
        plaintext[k++]=rail[i][railIndex[i]];
        railIndex[i]++;
        if(i==rails-1){
            for(j = i-1; j >=0;j--){
                if(k==n){
                    break;
                }
                plaintext[k++]=rail[j][railIndex[j]];
                railIndex[j]++;
                if(j==0){
                    i=0;
                }
            }
        }
    }

    plaintext[k]='\0';

    for(int i = 0; i < rails; i++){
        free(rail[i]);
    }
    free(rail);
    char *temp=add_ommited(plaintext,6);
    free(plaintext);
    return temp;
}