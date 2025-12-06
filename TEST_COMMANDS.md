# SecureShare Test Commands

This guide provides a step-by-step workflow to test the entire SecureShare application using 3 terminal windows (simulating 3 users/containers).

**Prerequisites:**
- Docker environment running (`docker-compose up -d`).
- 3 open terminals, connected to `cli-1`, `cli-2`, and `cli-3`.

## Terminal 1: Admin & Auditor (cli-1)
*Used for system setup and auditing.*

### 1. Login as Admin
```bash
ss auth login
# Username: admin
# Password: admin
```

### 2. Create Users
*Run these commands and enter the inputs when prompted.*

**Create Alice (Security Officer & Receiver)**
```bash
ss users create
# Username: alice
# OTP: 123456
# Email: alice@example.com
# Name: Alice Smith
```

**Create Bob (Sender)**
```bash
ss users create
# Username: bob
# OTP: 123456
# Email: bob@example.com
# Name: Bob Jones
```

**Create Charlie (Auditor)**
```bash
ss users create
# Username: charlie
# OTP: 123456
# Email: charlie@example.com
# Name: Charlie Audit
```

### 3. Assign Roles
*Assign special roles to Alice and Charlie.*

```bash
# Make Alice a Security Officer
ss users assign-role alice --role SECURITY_OFFICER

# Make Charlie an Auditor
ss users assign-role charlie --role AUDITOR
```

---

## Terminal 2: Alice (Security Officer & Receiver) (cli-2)
*Alice will assign clearances and receive a file.*

### 1. Login
```bash
ss auth login
# Username: alice
# Password: (password from creation step)
```

### 2. Select Role
```bash
ss users role
# Select: SECURITY_OFFICER
```

### 3. Assign Clearances
*Alice gives Bob and herself clearance to handle TOP_SECRET files.*

```bash
# Give Bob TOP_SECRET clearance in Engineering
ss users assign-clearance bob --level TOP_SECRET --dept Engineering

# Give Herself TOP_SECRET clearance (to be able to read the file later)
ss users assign-clearance alice --level TOP_SECRET --dept Engineering
```

---

## Terminal 3: Bob (Sender) (cli-3)
*Bob will send a secure file to Alice.*

### 1. Login
```bash
ss auth login
# Username: bob
# Password: (password from creation step)
```

### 2. Select Clearance
```bash
ss users clearance
# Select: TOP_SECRET
```

### 3. Send File
```bash
# Create a dummy secret file
echo "The eagle has landed." > mission.txt

# Upload to Alice
ss transfers upload mission.txt --to <ALICE_USER_ID> --level TOP_SECRET --dept Engineering
```
*(Note: You can find Alice's ID by running `ss users list` in Terminal 1)*
**Copy the Transfer ID returned!**

---

## Terminal 2: Alice (Receiver) (cli-2)
*Back to Alice to download the file.*

### 1. Select Clearance (if not already active)
```bash
ss users clearance
# Select: TOP_SECRET
```

### 2. List & Download
```bash
# Check incoming transfers
ss transfers list

# Download the file
ss transfers download <TRANSFER_ID>
```
*Verify the file content:*
```bash
cat mission.txt
```

---

## Terminal 1: Charlie (Auditor) (cli-1)
*Switching to Charlie to audit the system.*

### 1. Login as Charlie
```bash
ss auth login
# Username: charlie
# Password: (password from creation step)
```

### 2. Select Role
```bash
ss users role
# Select: AUDITOR
```

### 3. Audit Logs
```bash
# View all logs
ss audit log
```

### 4. Validate Log
*Pick an ID from the log list to validate.*
```bash
ss audit validate <LOG_ID>
```
*(Note: The CLI will now automatically fetch the log, load your private key from the vault, sign the entry, and submit the validation)*
