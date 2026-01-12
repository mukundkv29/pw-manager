# Password Manager (pw-man)

A secure, command-line password manager written in C that encrypts and stores user credentials locally.
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
./pw_man create <username>
```

**Example:**
```bash
./pw_man create MyUserName
Enter Password:
Retype Password:
```

### 2. Add a New Credential

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

### 3. Retrieve a Stored Password

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

### 4. Retrieve all Stored Passwords

```bash
./pw_man list <username> <master_password>
```

**Example:**
```bash
./pw_man list MyUserName MySecurePassword123
```

**Output:**
```
Listing all records...
-----------------------------

Record 1:
Alias: user
Website: website.com
Password: Password@123

Record 2:
Alias: user1
Website: website2.com
Password: Password@1234
```


### 5. Delete credential for a Website

```bash
./pw_man delete <username> <master_password> <website>
```

**Example:**
```bash
./pw_man delete MyUserName MySecurePassword123 website2.com
```

**Output:**
```
Deleting credential...
-----------------------------
Credential for website website2.com marked as deleted.
-----------------------------
```

### 6. Update credential for a Website

```bash
./pw_man update <username> <master_password> <website> <new_alias> <new_password>
```

**Example:**
```bash
./pw_man delete MyUserName MySecurePassword123 website.com newUser NewPassword@123
```

**Output:**
```
Updating credential...
-----------------------------
Credential for website website.com updated.
-----------------------------
```


