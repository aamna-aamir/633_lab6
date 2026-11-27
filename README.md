
# CPS633 Lab 6

# 1. OLMHash Password Scheme

This program implements a password management system using the OLMHash hashing algorithm.

### Features
- Allows users to register a new user ID and password.
- Verifies existing users using their stored password hash.
- Allows users to update their passwords after successful verification.
- Locks the account after 3 unsuccessful password attempts. The attempt counter resets when the program is restarted.
- Stores user IDs and their 96-bit password hashes in `table.txt`.

### Password Requirements
- User IDs must be between 4 and 31 characters.
- Passwords can contain uppercase letters, lowercase letters, and numbers.
- Passwords are converted to uppercase, padded with null bytes or truncated to 12 bytes, and hashed using the provided `E()` function.

### Compile and Run

```bash
gcc -Wall -Wextra -std=c11 olmhash.c -o olmhash
./olmhash
```

The program creates `table.txt` automatically if it does not already exist.



# Part 2: Challenge Response Authentication

This program enhances the OLMHash password management scheme, through the addition of a challenge, r.

### Features
- Allows users to register a new user ID and password.
- Generates new challenge, r, for each login attempt
- Verifies existing users using their stored password hash and challenge.
- Stores user IDs and their 96-bit password hashes in `table.txt`.

### Password Requirements
- User IDs must be between 4 and 31 characters.
- Passwords can contain uppercase letters, lowercase letters, and numbers (no special chars).
- Passwords are converted to uppercase, padded with null bytes or truncated to 12 bytes, and hashed using the provided `E()` function.

### Compile and Run

#### Enroll New Users
```bash
gcc 2_challenge_response_auth.c -o challenge_response
./challenge_response enroll
```

#### Validate Exiting Users
```bash
gcc 2_challenge_response_auth.c -o challenge_response
./challenge_response
```

The program creates `table.txt` automatically if it does not already exist.



# Part 3: Password Cracker



# Part 4: Real Life Password Cracker

Uses Ophcrack, a real password cracking tool (not something we wrote), to crack LM hash passwords with a free rainbow table.

### Files
- `Dockerfile` - builds an Ubuntu container with `ophcrack-cli` installed and a free LM-hash rainbow table unzipped inside it.
- `lmhash.py` - computes the real LM hash for a given password (upper-case, pad to 14 bytes, split into two 7-byte halves, DES-encrypt a fixed string with each half).
- `pwdump.txt` - the 4 test password hashes fed into Ophcrack, in standard pwdump format (`username:uid:LMHASH:NTHASH:::`).

### Compile and Run

```bash
docker build -t ophcrack .
docker run --rm -it ophcrack bash -c "ophcrack-cli -t /tables/<table_dir> -f pwdump.txt"
```

Ophcrack has no native macOS build, so it's run inside Docker. You'll need a free Ophcrack rainbow table (e.g. `tables_xp_free_fast.zip`) placed in this folder before building, since the table itself isn't included here due to size.

