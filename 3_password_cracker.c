//CPS633 Lab 6-Part 3: Password Cracker

#include <stdio.h>
#include <string.h>

#define N (26*26*26*26)// 456976 total pws (4 letters each letter could be any 26 letter)

// creating the tables
char pws[N][5]; //pasword 
char hsh[N][25]; //hash

// from the lab, encryption function
void E(char *in, char *out){
   out[0]=(in[0]&0x80)^(((in[0]>>1)&0x7F)^((in[0])&0x7F));
   out[1]=((in[1]&0x80)^((in[0]<<7)&0x80))^(((in[1]>>1)&0x7F)^((in[1])&0x7F));
   out[2]=((in[2]&0x80)^((in[1]<<7)&0x80))^(((in[2]>>1)&0x7F)^((in[2])&0x7F));
   out[3]=((in[3]&0x80)^((in[2]<<7)&0x80))^(((in[3]>>1)&0x7F)^((in[3])&0x7F));
}

// takes password and turns it into a 12-byte hash
void hashPwd(char *pw, char *h){
    char box[12];
    int len = strlen(pw);

    // pad to length 12 with 0's
    for (int i = 0; i < 12; i++)
        box[i] = 0;

    // copy from pw 
    for (int i = 0; i < len; i++)
        box[i] = pw[i];

    // encrypt each 4 char block
    E(&box[0], &h[0]);
    E(&box[4], &h[4]);
    E(&box[8], &h[8]);
}

// turing the 12 bytes from encryption to hex text
void toHex(char *h, char *hex){
    char digits[] = "0123456789abcdef"; // the 16 hex characters
    int pos = 0;
    int i;

    for (i = 0; i < 12; i++) {
        unsigned char b = h[i]; // one byte, 0 to 255
        int f = b / 16; // first hex digit
        int s  = b % 16; // second hex digit

        hex[pos] = digits[f]; // write first digit
        pos++;
        hex[pos] = digits[s]; // write second digit
        pos++;
    }
    hex[24] = '\0'; //end
}

int main(){
    char c0, c1, c2, c3; // the 4 letters
    int cnt = 0; // how many pws added
    char pw[5]; // cur pw
    char h[12]; // its hash in bytes
    char g[25]; // the hash we wanna crack

    // first we gotta create the table storing all 4 letter pws
    for (c0 = 'A'; c0 <= 'Z'; c0++)
      for (c1 = 'A'; c1 <= 'Z'; c1++)
        for (c2 = 'A'; c2 <= 'Z'; c2++)
          for (c3 = 'A'; c3 <= 'Z'; c3++) {
              pw[0] = c0;
              pw[1] = c1;
              pw[2] = c2;
              pw[3] = c3;
              pw[4] = '\0';

              hashPwd(pw, h); // get its hash
              strcpy(pws[cnt], pw); // save pw
              toHex(h, hsh[cnt]); // save hash as text
              cnt++;
          }

    // now given a hash, we can seach the table and return the correlating password
    printf("enter hash: ");
    scanf("%24s", g);

    for (int i = 0; i < cnt; i++) {
        if (strcmp(hsh[i], g) == 0) {
            printf("pw is: %s\n", pws[i]);
            return 0;
        }
    }

    return 0;
}  
