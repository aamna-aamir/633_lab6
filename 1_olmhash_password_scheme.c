/* CPS633 - Lab 6 (Aamna, Maarya, Rory, Umar)
 * ============================================================================
 * Part 1: OLMHash Password Scheme
 * ============================================================================
 */

// Task: This allows the user to register a new account, verify an existing password, update and existing password + limit uncesscful password attempts

// imports 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <time.h>


// configurations 
#define TABLE_FILE "table.txt" // stores user ids + hashed & XORed passwords
#define TEMP_FILE "table.tmp"  // temp file used when updating a pswd
#define MAX_ATTEMPTS 3 // num of max unsuccessful password attempts allower
#define HASH_LEN 12 // pswd hash need to be 12 bytes (aka 96 bits)
#define HASH_HEX_SIZE (2 * HASH_LEN + 1) // each hash needs to have 24 hexadecimal chars 

// userid needs to be min 4 and max 31 chars
#define MIN_ID 4
#define MAX_ID 31
#define MAX_PW 12 // only the first 12 password chars are used


/********************* E function *************************/
// DES replacement cipher
// The function E takes 4 bytes from *in as input and writes 4 bytes to *out
// func is applied separately to each of the three 4-byte password blocks

void E(char *in, char *out) {
    out[0] = (in[0] & 0x80) ^ (((in[0] >> 1) & 0x7F) ^ (in[0] & 0x7F));
    out[1] = ((in[1] & 0x80) ^ ((in[0] << 7) & 0x80)) ^ (((in[1] >> 1) & 0x7F) ^ (in[1] & 0x7F));
    out[2] = ((in[2] & 0x80) ^ ((in[1] << 7) & 0x80)) ^ (((in[2] >> 1) & 0x7F) ^ (in[2] & 0x7F));
    out[3] = ((in[3] & 0x80) ^ ((in[2] << 7) & 0x80)) ^ (((in[3] >> 1) & 0x7F) ^ (in[3] & 0x7F));
}



/********************* OLMHASH *************************/
void olm_hash(const char *password, unsigned char hash[HASH_LEN]) {
    char padded_pw[MAX_PW]; // array holding formatted 12 byte pswd
    memset(padded_pw, 0, sizeof padded_pw); // filling array w null chars (will automatically pad the shorter pswds)

    // preprocessing only first 12 chars
    for (int i = 0; i < MAX_PW && password[i] != '\0'; i++) {
        padded_pw[i] = (char)toupper((unsigned char)password[i]);
    }

    // apply encryption alg E() to each 4-byte block.
    for (int block = 0; block < 3; block++) {
        char *in = &padded_pw[block * 4];
        char *out = (char *)&hash[block * 4];
        E(in,out);
    }
}


// convert hash to hex so it can be stored in a text file (12 bytes -> 24 chars)
void hash_to_hex(const unsigned char *hash, char *hex) {
    for (int i = 0; i < HASH_LEN; i++) {
        sprintf(hex + (2 * i), "%02x", hash[i]); // the %02x prints each byte as 2 hex digits
    }

    hex[2 * HASH_LEN] = '\0'; // ending w a null terminator
}

// convert hex to hash (24 chars -> 12 bytes)
int hex_to_hash(const char *hex, unsigned char *hash) {
    if (strlen(hex) != 2 * HASH_LEN) // valid hash = 24 chars
        return 0;

    for (int i = 0; i < HASH_LEN; i++) {
        // both chars should be valid hex digits
        if (!isxdigit((unsigned char)hex[2 * i]) || !isxdigit((unsigned char)hex[2 * i + 1])) {
            return 0;
        }

        unsigned int value;

        // convert the 2 hex chars into 1 byte
        if (sscanf(hex + (2 * i), "%2x", &value) != 1)
            return 0;

        hash[i] = (unsigned char)value;
    }

    return 1;
}


/********************* Validate user id *************************/
int valid_user_id(const char *id) {
    size_t length = strlen(id);

    //  check min and max length 
    if (length < MIN_ID || length > MAX_ID)
        return 0;

    // reject tabs, spaces or other whitespace -> only numbers + uppercase & lowercase letters are allowed 
    for (size_t i = 0; i < length; i++) {
        if (isspace((unsigned char)id[i]))
            return 0;
    }

    return 1;
}

/********************* Validate password *************************/
int valid_password(const char *password) {
    // an empty password is invalid
    if (password[0] == '\0')
        return 0;

    // only validating first 12 chars -- since thats all that will be used
    for (int i = 0; i < MAX_PW && password[i] != '\0'; i++) {
        char c = password[i];

        // accept only A-Z, a-z, and 0-9
        if (!((c >= 'A' && c <= 'Z') ||
              (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9')))
        {
            return 0;
        }
    }

    return 1;
}

/********************* read user input *************************/
int read_input(const char *prompt, char *buffer, size_t size) {
    printf("%s", prompt);
    fflush(stdout);

    // read input from the keyboard, storing at most size-1 chars + null terminator
    if (fgets(buffer, (int)size, stdin) == NULL)
        return 0;

    // removing newline chars 
    size_t length = strlen(buffer);
    if (length > 0 && buffer[length - 1] == '\n') {
        buffer[length - 1] = '\0';
    }
    else {
        // discard remaining input if the user entered more than size-1 chars
        int c;
        while ((c = getchar()) != '\n' && c != EOF) {
            // Discard extra characters
        }
    }

    // also remove carriage return if present
    length = strlen(buffer);
    if (length > 0 && buffer[length - 1] == '\r')
        buffer[length - 1] = '\0';

    return 1;
}


/********************* Find existing user *************************/
int find_user(const char *user_id, unsigned char stored_hash[HASH_LEN]) {
    FILE *file = fopen(TABLE_FILE, "r");

    // if the file doesnt exist, return 0 (user not found)
    if (file == NULL)
        return 0;

    char file_id[64];
    char file_hash[64];

    // read userid + hash from the file, one line at a time
    while (fscanf(file, "%63s %63s", file_id, file_hash) == 2) {
        if (strcmp(file_id, user_id) == 0) { // compare stored + entered user id
            // convert stored hex back to hash
            int result = hex_to_hash(file_hash, stored_hash);
            fclose(file);
            return result;
        }
    }

    fclose(file);
    
    // fallback when user isnt found
    return 0;
}


/********************* Add a new user *************************/
int add_user(const char *user_id, const unsigned char *hash) {
    
    FILE *file = fopen(TABLE_FILE, "a");
    if (file == NULL){
        printf("Error opening password table.\n");
        return 0;
    }

    char hex[HASH_HEX_SIZE];
    hash_to_hex(hash, hex); // convert raw hash into hex
    // store user id + hash separated by a space
    fprintf(file, "%s %s\n", user_id, hex);

    fclose(file);
    return 1;
}

/********************* Update existing user *************************/
int update_user(const char *user_id, const unsigned char *new_hash) {
    FILE *file = fopen(TABLE_FILE, "r");
    if (file == NULL)
        return 0;

    FILE *temp = fopen(TEMP_FILE, "w" );
    if (temp == NULL) {
        fclose(file);
        return 0;
    }

    char line[256];
    char file_id[64];
    char file_hash[64];
    char new_hex[HASH_HEX_SIZE];

    // convert new hash into hex (password hash = new_hex)
    hash_to_hex(new_hash, new_hex);

    int found = 0;

    // reach each existing record
    while (fgets(line, sizeof(line), file) !=NULL){
        // check whether curr record contains a userid + hash & whether it matches user id of account being updated
        if (sscanf(line, "%63s %63s", file_id, file_hash) == 2 && strcmp(file_id, user_id) == 0){
            fprintf(temp, "%s %s\n", user_id, new_hex); // weite user with updated password hash
            found = 1;
        } else {
            // preserve all other users records
            fputs(line, temp); 
        }
    }

    fclose(file);
    fclose(temp);

    // if user not found, remove temp file + cancle the update
    if (!found) {
        remove(TEMP_FILE);
        return 0;
    }

    // replace original table with the updated temp file
    if (rename(TEMP_FILE, TABLE_FILE) != 0){
        printf("Error updating password table.\n");
        remove(TEMP_FILE);
        return 0;
    }

    return 1;
}


/********************* Main Program *************************/
int main(void) {

    // user input
    char user_id[512];
    char password[512];

    // arrays for storing password ashes
    unsigned char stored_hash[HASH_LEN];
    unsigned char entered_hash[HASH_LEN];
    unsigned char new_hash[HASH_LEN];

    // password table (creates if it doesnt exist)
    FILE *file = fopen(TABLE_FILE, "a");

    if (file == NULL) {
        printf("Unable to create password table.\n");
        return 1;
    }

    fclose(file);


    printf("===== OLMHash Password Scheme =====\n\n");

    // request user id
    if (!read_input("Enter user ID: ", user_id, sizeof(user_id))) {
        return 1;
    }

    // check whether the entered user id is valid
    if (!valid_user_id(user_id)) {
        printf("User ID is invalid. It must be between 4 and 31 characters with no spaces.\n");
        return 1;
    }

    // 1. new user registration
    // make sure user doesn't already exist
    if (!find_user(user_id, stored_hash)) {
        printf("\nNew user detected.\n");

        // keep asking until a valid password is entered
        while (true) {
            if (!read_input("Enter a new password: ",password, sizeof(password))) {
                return 1;
            }

            if (valid_password(password))
                break;

            printf("Password is Invalid. Use letters and numbers only. Make sure it's between 4 and 31 characters with no spaces.\n");
        }

        // once we get valid password, hash it
        olm_hash(password, new_hash);

        // add new user + hash to tabl
        if (add_user(user_id, new_hash) ){
            printf("\nUser: %s was successfully registered.\n", user_id);
        }

        return 0;
    }


    // 2. if we have an esiting user
    printf("\nExisting user detected.\n");

    // keep track of password attempts
    int attempts = 0;

    // verify the old password
    while (attempts < MAX_ATTEMPTS)
    {
        if (!read_input("Enter your old password: ", password, sizeof(password))) {
            return 1;
        }

        // validating + hashing old password
        if (valid_password(password)) {
            olm_hash(password, entered_hash);

            // compare entered hash with stored hash (only first 12 chars)
            if (memcmp(entered_hash, stored_hash, HASH_LEN ) == 0) {
                printf("\nPassword has been verified.\n");

                // ask for new password
                while (true) {
                    if (!read_input("Enter your new password: ", password, sizeof(password))) {
                        return 1;
                    }

                    if (valid_password(password))
                        break;
                    
                    printf("Password is Invalid. Use letters and numbers only. Make sure it's between 4 and 31 characters with no spaces.\n");
                }

                // new password hash
                olm_hash(password, new_hash);

                // replace old hash in the table
                if (update_user(user_id, new_hash)) {
                    printf("\nPassword was successfully updated.\n");
                }

                return 0;
            }
        }

        // increase incorrect attemp (if password couldnt be validated + verified)
        attempts++;

        printf("Incorrect password. You have %d attempts remaining\n", MAX_ATTEMPTS - attempts);
    }

    // maximum incorrect password attempts reaches
    printf("\nToo many unsuccessful attempt, your account is now locked\n");

    return 0;
}
