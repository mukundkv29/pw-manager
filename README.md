# Password Manager (pw-man)

A secure, command-line password manager written in C that encrypts and stores user credentials locally. This project demonstrates encryption, secure password hashing, and file I/O operations.

### Installation of Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get install gcc libssl-dev
```

**macOS (using Homebrew):**
```bash
brew install openssl
```

**Windows (MinGW):**
```bash
# Install MinGW and OpenSSL development libraries
# Or use pre-compiled OpenSSL binaries
```

## Building the Project

Compile the program using GCC with OpenSSL libraries:

```bash
gcc -o pw_man pw_man_main.c -lssl -lcrypto
```

## Usage

### 1. Create a New Vault

Initialize a new password vault with your master credentials:

```bash
./pw_man create <username> <master_password>
```

**Example:**
```bash
./pw_man create MyUserName MySecurePassword123
```

This creates an encrypted file (`bfile.bin`) that stores all your passwords.

### 2. View Total Credentials Count

Check how many credentials are stored in your vault:

```bash
./pw_man read <username> <master_password>
```

**Example:**
```bash
./pw_man read MyUserName MySecurePassword123
```

### 3. Add a New Credential

Store a new password for a website or service:

```bash
./pw_man add <username> <master_password> <website> <alias> <password>
```

**Parameters:**
- `username`: Your master username
- `master_password`: Your master password
- `website`: The website URL or service name
- `alias`: A friendly name for this credential (e.g., "Gmail Account")
- `password`: The password to store for this service

**Example with website:**
```bash
./pw_man add MyUserName MySecurePassword123 gmail.com Gmail gmailpass456
```

### 4. Retrieve a Stored Password

Look up a password by searching for a website:

```bash
./pw_man get <username> <master_password> <website>
```

**Example:**
```bash
./pw_man get MyUserName MySecurePassword123 gmail.com
```

**Output:**
```
Searching records...
-----------------------------
Alias: Gmail
Password: gmailpass456
Website: gmail.com
-----------------------------
```
