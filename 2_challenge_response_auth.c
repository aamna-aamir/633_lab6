/* CPS633 - Lab 6 (Aamna, Maarya, Rory, Umar)
 * ============================================================================
 * Part 2: Challenge-Response Simulation
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <time.h>

#define TABLE_FILE "table.txt" /* stores user id and hashed+XORd password*/
#define HASH_LEN   12      /* 3 blocks x 4 bytes = 96 bits                */
#define HASH_BITS  (HASH_LEN * 8)
#define MIN_ID     4       /* user ids at least 4 characters              */
#define MAX_ID     31      /* user ids fewer than 32                      */
#define MAX_PW     12      /* passwords: only the first 12 chars count    */

/* ---------------- E function (as per assignment description) ----------------
 * Stand-in for DES to be called on each block. */
void E(char *in, char *out)
{
    out[0]=(in[0]&0x80)^(((in[0]>>1)&0x7F)^((in[0])&0x7F));
    out[1]=((in[1]&0x80)^((in[0]<<7)&0x80))^(((in[1]>>1)&0x7F)^((in[1])&0x7F));
    out[2]=((in[2]&0x80)^((in[1]<<7)&0x80))^(((in[2]>>1)&0x7F)^((in[2])&0x7F));
    out[3]=((in[3]&0x80)^((in[2]<<7)&0x80))^(((in[3]>>1)&0x7F)^((in[3])&0x7F));
}

/* ---------------- Part 1 HASHING --> to be updated when pt1 complete ----------------
 * Params:  password --> the input string
 *          hash --> the 12-byte (HASH_LEN) output buffer
 * Returns: void (output is written directly in hash buffer)
*/

void olm_hash(const char *password, unsigned char hash[HASH_LEN])
{
    /* Sets every byte to null character \0 to handle padding rule
        so any password with len < 12 has padding*/
    char padded_pw[MAX_PW];
    memset(padded_pw, 0, sizeof padded_pw);

    /* Copy at most 12 uppercased characters (extras are ignored) from password to padded array
     * If the password is shorter, the rest stays '\0'. 
     ex. Hello123 becomes H E L L O 1 2 3 \0 \0 \0 \0 */
    for (int i = 0; i < MAX_PW && password[i] != '\0'; i++)
        padded_pw[i] = (char)toupper((unsigned char)password[i]);

    /* Hash each 4-byte block independently with E().*/
    for (int block = 0; block < 3; block++)
        E(&padded_pw[block * 4], (char *)&hash[block * 4]);
}

/* ========== HELPER FUNCTIONS ========== */

/* VALIDATE USER ID */
/* Params: id -->  input string
 * Returns: 1 if valid user_id, 0 if invalid*/
static int valid_id(const char *id)
{
    size_t len = strlen(id);
    /*User ID is invalid if < 4 or  > 32 chars*/
    if (len < MIN_ID || len > MAX_ID) return 0;

    /*User ID is invalid if it contains whitespaces*/
    for (size_t i = 0; i < len; i++)
        if (isspace((unsigned char)id[i])) return 0;
    return 1;
}

/* VALIDATE PASSWORD */
/* Params: pw --> input string
 * Returns: 1 if valid, 0 if invalid*/
static int valid_password(const char *pw)
{
    /*Password cannot contain whitespaces*/
    if (pw[0] == '\0') return 0;

    /*Password cannot contain special characters (only A-Z, a-z, 0-9)*/
    for (size_t i = 0; pw[i]; i++)
        if (!isalnum((unsigned char)pw[i])) return 0;
    return 1;
}

/* READ AND CLEAN INPUT */
/* Params:  prompt --> string printed out to client
            buf --> holds the input entered by user
            size --> max length of input read
    Return: void
*/
static void get_input(const char *prompt, char *buf, size_t size)
{
    /*Print a prompt*/
    printf("%s", prompt);

    /*Ends immediately because input doesn't end in newline char*/
    fflush(stdout);

    /*Reads from keyboard until newline, storing at most size-1 chars + \0*/
    if (!fgets(buf, (int)size, stdin)) { buf[0] = '\0'; return; }

    /*Remove newline because id's and passwords are stored without it*/
    buf[strcspn(buf, "\r\n")] = '\0';
}

/* CONVERT 12 RAW BYTES TO 24 HEX CHARS + \0 */
/* Params:  in --> 12 raw hash bytes
            out --> buffer where hex is written to
    Return: void
*/
static void to_hex(const unsigned char *in, char *out)
{
    /*Loop once per byte (12 times), converting to hex in lowercase using %02x*/
    for (int i = 0; i < HASH_LEN; i++)
        sprintf(out + 2 * i, "%02x", in[i]);
}

/* CONVERT 24 HEX CHARS TO 12 RAW BYTES */
/* Params:  hex --> input hex to read
            out --> output 12-byte array
   Returns: 1 if successful conversion, 0 otherwise
*/
static int from_hex(const char *hex, unsigned char *out)
{
    /* Break early if input is not 24 hex chars*/
    if (strlen(hex) != 2 * HASH_LEN) return 0;

    /*Convert 2 chars at a time from hex back to raw-byte values*/
    for (int i = 0; i < HASH_LEN; i++) {
        unsigned int v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1) return 0;
        out[i] = (unsigned char)v;
    }
    return 1;
}

/* LOOKUP ID */
/* Params:  id --> user id
            hash --> to be filled in if id is found in table
   Returns: 1 if found, 0 otherwise
*/
static int table_lookup(const char *id, unsigned char hash[HASH_LEN])
{
    /*File not found, or nobody is enrolled yet*/
    FILE *fp = fopen(TABLE_FILE, "r");
    if (!fp) return 0;

    char fid[64], fhex[64];
    int found = 0;
    /* Read one "id + hex" per line */
    while (fscanf(fp, "%63s %63s", fid, fhex) == 2) {   
        /* Compares input id to stored id, evaluating to true when identical
           then from_hex converts hex text to raw bytes, writing them into hash which returns 1 if valid.
           This ensures a matching id with invalid/damaged hex is "not found"*/
        if (strcmp(fid, id) == 0 && from_hex(fhex, hash)) {
            found = 1;
            break;
        }
    }
    /*Close file and return*/
    fclose(fp);
    return found;
}

/* ============================================================================
 * FINAL PROTOCOL IMPLEMENTATION
 * ============================================================================ */

/* SERVER COMPUTING f(r,h) ie. bitewise XOR of the 32-bit challenge r with the 96-bit hash h.
 * Extract both bits, XOR them, and write the result bit into `out`.
 *
 * XOR is its own inverse, so f(r, f(r, h)) == h. Both client and server use
 * this same function, which is why matching hashes give matching results.
 * Params: r --> server generated random 32-bit integer
 *         h --> 12-byte hash
 *         out --> 12-byte array where the XOR'd result is stored
 * Returns: void
 */
static void f(uint32_t r, const unsigned char h[HASH_LEN], unsigned char out[HASH_LEN])
{
    memset(out, 0, HASH_LEN);                          /* build result from zero */

    /*For every bit position i = 0..95 of the hash (MSB-first)*/
    for (int i = 0; i < HASH_BITS; i++) {
        int byte_idx = i / 8;                          /* which byte it lives in: i / 8 (since 8 bits = 1 byte)*/
        int bit_idx  = 7 - (i % 8);                    /* position of bit inside that byte: 7 - (i % 8) (7 = MSB, 0 = LSB)*/

        int h_bit = (h[byte_idx] >> bit_idx) & 1;      /* extracting bit i of the hash (& 1 gives just 0 or 1)
                                                          value >> n moves the bit so it's in the right most position (MSB)*/
        int r_bit = (int)((r >> (31 - (i % 32))) & 1); /* extracting matching bit of r, where i%32 wraps around 32-bit r */

        int x = h_bit ^ r_bit;                         /* the bit-wise XOR       */

        out[byte_idx] |= (unsigned char)(x << bit_idx);/* place it in the result */
    }
}

/* SERVER GENERATING FRESH 32-bit r FOR EACH LOGIN
   Params: n/a
   Returns: r --> random 32-bit integer (similar to a nonce)
*/
static uint32_t generate_challenge_r(void)
{
    uint32_t r = 0;
    /*Opens special file in Linux that generates random number using OS's random number generator*/
    FILE *fp = fopen("/dev/urandom", "rb");
    if (fp) {
        /*Reads 4 random bytes (8*4 = 32 bits) and stores them in r*/
        if (fread(&r, sizeof r, 1, fp) == 1) { fclose(fp); return r; }
        fclose(fp);
    }
    /*Fallback random number generator incase special file is not located
      Generates 2 pseudo-random int, converts them to unsigned 32-bit int, shift bits 16 positions to the left
      then XOR them together to yield the final random r*/
    srand((unsigned)time(NULL));
    return ((uint32_t)rand() << 16) ^ (uint32_t)rand();
}

/* GENERATE CLIENTS AUTHENTICATION RESPONSE
 * Params: password --> users input password
           r --> random challenge generated by server
           response --> stores the hashed, XOR'd password
   Returns: void
*/
static void client_response(const char *password, uint32_t r, unsigned char response[HASH_LEN])
{
    unsigned char h[HASH_LEN];
    /*hash the typed password*/
    olm_hash(password, h);   
    
    /*compute f(r,h)*/
    f(r, h, response);
}

/* SERVER SIDE-AUTHENTICATION TO VERIFY USER
   Params: id --> user id of client
           r --> random challenge generated by server
           response --> authentication response recieved from client
    Returns: 1 if authentication granted, 0 otherwise
*/
static int server_verify(const char *id, uint32_t r, const unsigned char response[HASH_LEN])
{

    unsigned char h_stored[HASH_LEN]; /*stores the password hash retrived from the servers user table*/
    unsigned char expected[HASH_LEN]; /*stores the response the server calculates*/

    /* The user id must already exist in the table, else authentication fails. */
    if (!table_lookup(id, h_stored))
        return 0;

    /* Calculate expected response by computing f(r, h') using the hash h' stored in the table*/
    f(r, h_stored, expected);                           

    /* If client entered correct password, response = expected */
    /* memcmp performs byte-wise comparison between expected and response */
    return memcmp(expected, response, HASH_LEN) == 0;
}

/* ---------------- Test helper: add an entry to the table ----------------
 * Lets you try the protocol before your Part 1 program is finished. */
static void enroll(void)
{
    char id[128], pw[128];
    get_input("New user id: ", id, sizeof id);
    if (!valid_id(id)) { printf("Invalid user id (4-31 chars, no spaces).\n"); return; }
    get_input("New password: ", pw, sizeof pw);
    if (!valid_password(pw)) { printf("Passwords: letters and digits only.\n"); return; }

    unsigned char h[HASH_LEN];
    char hex[2 * HASH_LEN + 1];
    olm_hash(pw, h);
    to_hex(h, hex);

    FILE *fp = fopen(TABLE_FILE, "a");
    if (!fp) { perror("fopen"); return; }
    fprintf(fp, "%s %s\n", id, hex);
    fclose(fp);
    printf("Added.\n");
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "enroll") == 0) {
        enroll();
        return 0;
    }

    char id[128], pw[128];

    /* Step 1: CLIENT -> SERVER: the user id. */
    get_input("User id: ", id, sizeof id);
    if (!valid_id(id)) { printf("access denied\n"); return 0; }
    printf("[client -> server] user id: %s\n", id);

    /* Step 2: SERVER -> CLIENT: random 32-bit challenge r. Sent even for
     * unknown ids, so the server doesn't reveal which ids exist. */
    uint32_t r = generate_challenge_r();
    printf("[server -> client] challenge r = 0x%08X\n", (unsigned)r);

    /* Step 3: CLIENT -> SERVER: f(r, h), computed from the typed password. */
    get_input("Password: ", pw, sizeof pw);
    if (!valid_password(pw)) { printf("access denied\n"); return 0; }

    unsigned char response[HASH_LEN];
    client_response(pw, r, response);

    char hex[2 * HASH_LEN + 1];
    to_hex(response, hex);
    printf("[client -> server] response: %s\n", hex);

    /* Step 4: SERVER checks the response against its own f(r, h'). */
    if (server_verify(id, r, response))
        printf("access granted\n");
    else
        printf("access denied\n");

    return 0;
}