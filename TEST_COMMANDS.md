# SecureShare Test Commands

This guide provides a step-by-step workflow to test the entire SecureShare application using 3 terminal windows (simulating 3 users/containers).

**Prerequisites:**
- Docker environment running (`docker-compose up -d`).
- 3 open terminals, connected to `cli-1`, `cli-2`, and `cli-3`.

## Terminal 1: Admin & Auditor (cli-1)
*Used for system setup and auditing.*

### 1. Login as Admin
```bash
secureshare auth login
# Username: admin
# Password: admin
```

### 2. Create Users
*Run these commands and enter the inputs when prompted.*

**Create Alice (Security Officer & Receiver)**
```bash
secureshare users create
# Username: alice
# OTP: 123456
# Email: alice@example.com
# Name: Alice Smith
```

**Create Bob (Sender)**
```bash
secureshare users create
# Username: bob
# OTP: 123456
# Email: bob@example.com
# Name: Bob Jones
```

**Create Charlie (Auditor)**
```bash
secureshare users create
# Username: charlie
# OTP: 123456
# Email: charlie@example.com
# Name: Charlie Audit
```

### 3. Assign Roles
*Assign special roles to Alice and Charlie.*

```bash
# Make Alice a Security Officer
secureshare users assign-role alice --role SECURITY_OFFICER

# Make Charlie an Auditor
secureshare users assign-role charlie --role AUDITOR
```

---

## Terminal 2: Alice (Security Officer & Receiver) (cli-2)
*Alice will assign clearances and receive a file.*

### 1. Login
```bash
secureshare auth login
# Username: alice
# Password: (password from creation step)
```

### 2. Select Role
```bash
secureshare users role
# Select: SECURITY_OFFICER
```

### 3. Assign Clearances
*Alice gives Bob and herself clearance to handle TOP_SECRET files.*

```bash
# Give Bob TOP_SECRET clearance in Engineering
secureshare users assign-clearance bob --level TOP_SECRET --dept Engineering

# Give Herself TOP_SECRET clearance (to be able to read the file later)
secureshare users assign-clearance alice --level TOP_SECRET --dept Engineering
```

---

## Terminal 3: Bob (Sender) (cli-3)
*Bob will send a secure file to Alice.*

### 1. Login
```bash
secureshare auth login
# Username: bob
# Password: (password from creation step)
```

### 2. Select Clearance
```bash
secureshare users clearance
# Select: TOP_SECRET
```

### 3. Send File
```bash
# Create a dummy secret file
echo "The eagle has landed." > mission.txt

# Upload to Alice
secureshare transfers upload mission.txt --to <ALICE_USER_ID> --level TOP_SECRET --dept Engineering
```
*(Note: You can find Alice's ID by running `secureshare users list` in Terminal 1)*
**Copy the Transfer ID returned!**

---

## Terminal 2: Alice (Receiver) (cli-2)
*Back to Alice to download the file.*

### 1. Select Clearance (if not already active)
```bash
secureshare users clearance
# Select: TOP_SECRET
```

### 2. List & Download
```bash
# Check incoming transfers
secureshare transfers list

# Download the file
secureshare transfers download <TRANSFER_ID>
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
secureshare auth login
# Username: charlie
# Password: (password from creation step)
```

### 2. Select Role
```bash
secureshare users role
# Select: AUDITOR
```

### 3. Audit Logs
```bash
# View all logs
secureshare audit log
```

### 4. Validate Log
*Pick an ID from the log list to validate.*
```bash
secureshare audit validate <LOG_ID> <SIGNATURE>
```
*(Note: In a real scenario, you would verify the signature externally, but here we just mark it as validated)*
