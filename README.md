# 633_lab6

==================================================
1. OLMHash Password Scheme
==================================================
This program implements a password management system using the OLMHash hashing algorithm.

**Features:**
- Allows users to register a new user ID and password.
- Verifies existing users using their stored password hash.
- Allows users to update their passwords after successful verification.
- Locks the account after 3 unsuccessful password attempts. The attempt counter resets when the program is restarted.
- Stores user IDs and their 96-bit password hashes in `table.txt`.

**Password Requirements:**
- User IDs must be between 4 and 31 characters.
- Passwords can contain uppercase letters, lowercase letters, and numbers.
- Passwords are converted to uppercase, padded with null bytes or truncated to 12 bytes, and hashed using the provided `E()` function.

**Compile and Run:**
```bash
gcc -Wall -Wextra -std=c11 olmhash.c -o olmhash
./olmhash
```
The program creates `table.txt` automatically if it does not already exist.

==================================================
2. Challenge Response Authentication
==================================================



==================================================
3. Password Cracker
==================================================