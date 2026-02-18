# Hedera + AWS KMS Signing Workshop

**Duration:** 45 minutes
**Level:** Intermediate
**Prerequisites:** AWS Account, Node.js 18+, Hedera Testnet Account

---

## Workshop Overview

Learn how to securely sign Hedera transactions using AWS Key Management Service (KMS). Your private keys never leave AWS infrastructure - only signatures are returned.

### What You'll Learn
- Set up AWS CLI and configure credentials
- Create an IAM user with KMS permissions
- Create a KMS key for secp256k1 signing (Hedera-compatible)
- Sign Hedera transactions using the KMS key
- Verify transactions on HashScan

---

## Why Use KMS for Blockchain Signing?

**The Problem:**
- Private keys stored in `.env` files, code, or memory
- Keys can be leaked, stolen, or accidentally committed
- Single point of failure for key management

**The Solution - KMS:**
- Keys generated and stored in tamper-resistant hardware (HSMs)
- Private key **never** leaves AWS infrastructure
- You send a hash → AWS returns a signature
- Audit logs, access controls, key rotation built-in

### Architecture Flow

```
┌─────────────────┐      ┌──────────────┐      ┌─────────────────┐
│  Your App       │      │   AWS KMS    │      │  Hedera Network │
│                 │      │              │      │                 │
│ 1. Create TX    │─────▶│ 2. Sign Hash │─────▶│ 3. Verify &     │
│    & Hash it    │      │   (secp256k1)│      │    Execute TX   │
│                 │◀─────│ Return Sig   │      │                 │
└─────────────────┘      └──────────────┘      └─────────────────┘
```

---

## Step 1: Clone & Setup

```bash
git clone https://github.com/hedera-dev/aws-kms-workshop.git
cd aws-kms-workshop
npm install
```

---

## Step 2: Configure Hedera Credentials

Get a testnet account at [portal.hedera.com](https://portal.hedera.com/) if you don't have one.

```bash
cp .env_sample .env
```

Edit `.env` with your Hedera credentials:

```bash
# Your existing Hedera testnet account (to fund new accounts)
HEDERA_ACCOUNT_ID=0.0.XXXXXX
HEDERA_PRIVATE_KEY=302e020100300506032b6570...
```

---

## Step 3: Install AWS CLI

**macOS (Homebrew):**
```bash
brew install awscli
```

**macOS (Official Installer):**
```bash
curl "https://awscli.amazonaws.com/AWSCLIV2.pkg" -o "AWSCLIV2.pkg"
sudo installer -pkg AWSCLIV2.pkg -target /
```

**Linux:**
```bash
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
```

**Windows:**
```powershell
msiexec.exe /i https://awscli.amazonaws.com/AWSCLIV2.msi
```

**Verify Installation:**
```bash
aws --version
# Output: aws-cli/2.x.x Python/3.x.x ...
```

---

## Step 4: Configure AWS CLI

### Create AWS Root Access Key (if needed)

If you don't have AWS credentials yet:

1. Log into [AWS Console](https://console.aws.amazon.com/)
2. Click your username (top right) → **Security credentials**
3. Scroll to **Access keys** → **Create access key**
4. Choose **Command Line Interface (CLI)**
5. Acknowledge the warning and create
6. **Save both keys immediately** - the secret key is shown only once!

### Configure the CLI

```bash
aws configure
```

You'll be prompted for:
```
AWS Access Key ID [None]: YOUR_ACCESS_KEY_ID
AWS Secret Access Key [None]: YOUR_SECRET_ACCESS_KEY
Default region name [None]: us-east-1
Default output format [None]: json
```

**Verify Configuration:**
```bash
aws sts get-caller-identity
```

Expected output:
```json
{
    "UserId": "AIDAXXXXXXXXXXXXXXXXX",
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/your-username"
}
```

---

## Step 5: Create IAM User & Policy

Create a dedicated IAM user (best practice - don't use root credentials):

```bash
# Create the IAM user
aws iam create-user --user-name hedera-kms-user
```

Expected output:
```json
{
    "User": {
        "UserName": "hedera-kms-user",
        "UserId": "AIDAXXXXXXXXXXXXXXXXX",
        "Arn": "arn:aws:iam::123456789012:user/hedera-kms-user",
        "CreateDate": "2024-01-15T10:00:00Z"
    }
}
```

### Create KMS Access Policy

```bash
cat > hedera-kms-policy.json << 'EOF'
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowKMSSigning",
            "Effect": "Allow",
            "Action": [
                "kms:Sign",
                "kms:GetPublicKey",
                "kms:DescribeKey"
            ],
            "Resource": "*"
        }
    ]
}
EOF
```

Create and attach the policy:

```bash
# Create the policy
aws iam create-policy \
    --policy-name HederaKMSSigningPolicy \
    --policy-document file://hedera-kms-policy.json

# Attach to user
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
aws iam attach-user-policy \
    --user-name hedera-kms-user \
    --policy-arn arn:aws:iam::${ACCOUNT_ID}:policy/HederaKMSSigningPolicy
```

---

## Step 6: Create KMS Key & Save to .env

This is the critical step - create an asymmetric key with the secp256k1 curve (required for Hedera):

```bash
# Create KMS key and extract the Key ID
AWS_KMS_KEY_ID=$(aws kms create-key \
    --key-spec ECC_SECG_P256K1 \
    --key-usage SIGN_VERIFY \
    --description "Hedera Transaction Signing Key" \
    --query 'KeyMetadata.KeyId' \
    --output text)

echo "Created KMS Key: $AWS_KMS_KEY_ID"
```

**Save the Key ID to your .env file:**

```bash
# Append the KMS Key ID to your .env file
echo "AWS_KMS_KEY_ID=$AWS_KMS_KEY_ID" >> .env
```

**Verify KMS Key Setup:**
```bash
# Describe the key
aws kms describe-key --key-id $AWS_KMS_KEY_ID
```

Expected output (key fields to verify):
```json
{
    "KeyMetadata": {
        "AWSAccountId": "123456789012",
        "KeyId": "e4ed5c9f-490d-4667-ae90-41a8717324fd",
        "Arn": "arn:aws:kms:us-east-1:123456789012:key/e4ed5c9f-...",
        "CreationDate": "2026-02-18T06:09:07.124000-07:00",
        "Enabled": true,
        "Description": "Hedera Transaction Signing Key",
        "KeyUsage": "SIGN_VERIFY",
        "KeySpec": "ECC_SECG_P256K1",
        "SigningAlgorithms": ["ECDSA_SHA_256"]
    }
}
```

**Key things to verify:**
- `"Enabled": true`
- `"KeySpec": "ECC_SECG_P256K1"` (required for Hedera)
- `"KeyUsage": "SIGN_VERIFY"`

```bash
# Verify public key is accessible
aws kms get-public-key --key-id $AWS_KMS_KEY_ID --output text --query 'PublicKey' | base64 -d | xxd | head -5
```

### Optional: Create an Alias

```bash
aws kms create-alias \
    --alias-name alias/hedera-signing-key \
    --target-key-id $AWS_KMS_KEY_ID
```

Now you can reference the key as `alias/hedera-signing-key` instead of the UUID.

---

## Step 7: Create IAM Access Keys & Save to .env

```bash
aws iam create-access-key --user-name hedera-kms-user
```

Expected output:
```json
{
    "AccessKey": {
        "UserName": "hedera-kms-user",
        "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
        "Status": "Active",
        "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "CreateDate": "2026-02-18T13:09:07+00:00"
    }
}
```

**⚠️ IMPORTANT:** Copy both `AccessKeyId` and `SecretAccessKey` now! The secret key is only shown once.

Verify your .env file has all required values:
```bash
cat .env
```

---

## Step 8: Run the Demo

```bash
npm start
```

Expected output:
```
=== AWS KMS Signing Demo ===
Using KMS Key ID: e4ed5c9f-490d-4667-ae90-41a8717324fd
KMS Key ARN: arn:aws:kms:us-east-1:123456789012:key/e4ed5c9f-...
Public Key (from KMS): 02edbf4926f65441dc403919dd884a8389b6ae2da400...
Creating a new account
The new account ID is: 0.0.XXXXXXX
0.0.XXXXXXX balance:  0.002 ℏ
Signing with KMS Key: e4ed5c9f-490d-4667-ae90-41a8717324fd
Signing with KMS Key: e4ed5c9f-490d-4667-ae90-41a8717324fd
...
The transfer transaction from my account to the new account was: SUCCESS
Check transaction here: https://hashscan.io/testnet/transaction/...
Done
```

### Verify KMS Was Used

**1. Check AWS CloudTrail for Sign operations:**

```bash
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=Sign --max-results 5
```

This shows recent KMS Sign operations, confirming your transactions were signed by KMS.

**2. Verify the public key matches HashScan:**

On HashScan, your account shows a public key like `0x02edbf4926...`. To confirm it matches your KMS key:

```bash
aws kms get-public-key --key-id $AWS_KMS_KEY_ID --output text --query 'PublicKey' | base64 -d | openssl ec -pubin -inform DER -conv_form compressed -outform DER 2>/dev/null | tail -c 33 | xxd -p
```

The output (e.g., `02edbf4926f65441dc403919dd884a8389b6ae2da4009892d49513c2250c1c1398`) should match the public key shown on HashScan (minus the `0x` prefix).

---

## Understanding the Code Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                          index.js Flow                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. FETCH PUBLIC KEY FROM KMS                                       │
│     └─▶ GetPublicKeyCommand → Parse hex → Create PublicKey object   │
│                                                                     │
│  2. CREATE HEDERA ACCOUNT                                           │
│     └─▶ Use funding account to create new account with KMS pubkey   │
│                                                                     │
│  3. SET UP CUSTOM SIGNER                                            │
│     └─▶ client.setOperatorWith(accountId, pubKey, transactionSigner)│
│                                                                     │
│  4. SIGN TRANSACTIONS (transactionSigner function)                  │
│     ├─▶ Receive transaction bytes                                   │
│     ├─▶ Create keccak256 hash of bytes                              │
│     ├─▶ Send hash to KMS → SignCommand                              │
│     ├─▶ Receive DER-encoded signature                               │
│     ├─▶ Parse ASN.1 → Extract r, s values                           │
│     └─▶ Return 64-byte raw signature (r || s)                       │
│                                                                     │
│  5. EXECUTE TRANSFER                                                │
│     └─▶ Send HBAR, verify receipt, display HashScan link            │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Key Code Sections

**1. KMS Client Setup:**
```javascript
const kmsClient = new KMSClient({
  credentials: {
    accessKeyId: process.env.AWS_KMS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_KMS_SECRET_ACCESS_KEY,
  },
  region: process.env.AWS_KMS_REGION,
});
```

**2. Transaction Signer (the magic happens here):**
```javascript
async function transactionSigner(bytesToSign) {
  // 1. Hash the transaction bytes with keccak256
  const dataHex = Buffer.from(bytesToSign).toString("hex");
  const hash = keccak256(`0x${dataHex}`);

  // 2. Send to KMS for signing
  const command = new SignCommand({
    KeyId: process.env.AWS_AWS_KMS_KEY_ID,
    Message: hash,
    SigningAlgorithm: "ECDSA_SHA_256",
    MessageType: "DIGEST"
  });
  const response = await kmsClient.send(command);

  // 3. Parse DER signature to raw format (r || s)
  let decoded = EcdsaSigAsnParse.decode(Buffer.from(response.Signature), "der");
  let r = decoded.r.toArray("be", 32);
  let s = decoded.s.toArray("be", 32);

  const result = new Uint8Array(64);
  result.set(r, 0);
  result.set(s, 32);
  return result;
}
```

**3. Using the Custom Signer:**
```javascript
// This tells Hedera SDK to use our transactionSigner for all signatures
client.setOperatorWith(newAccountId, newAccountPublicKey, transactionSigner);
```

---

## Troubleshooting

**Error: `AccessDeniedException`**
```
User: arn:aws:iam::... is not authorized to perform: kms:Sign
```
→ Check IAM policy is attached and has the correct key ARN

**Error: `InvalidKeySpec`**
```
The key spec must be ECC_SECG_P256K1
```
→ Delete and recreate the key with `--key-spec ECC_SECG_P256K1`

**Error: `HEDERA_PRIVATE_KEY not found`**
→ Make sure your `.env` file is configured and you ran `npm install`

**Error: `ECDSA signature invalid`**
→ Usually means the public key wasn't extracted correctly. Verify KMS key type.

---

## Cleanup

Remove resources after the workshop:

```bash
# Schedule key deletion (7 day minimum wait)
aws kms schedule-key-deletion --key-id $AWS_KMS_KEY_ID --pending-window-in-days 7

# Delete alias (if created)
aws kms delete-alias --alias-name alias/hedera-signing-key

# Delete IAM user access keys
aws iam delete-access-key --user-name hedera-kms-user --access-key-id $AWS_KMS_ACCESS_KEY_ID

# Detach policy from user
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
POLICY_ARN="arn:aws:iam::${ACCOUNT_ID}:policy/HederaKMSSigningPolicy"

aws iam detach-user-policy \
    --user-name hedera-kms-user \
    --policy-arn $POLICY_ARN

# Delete all non-default policy versions first
aws iam list-policy-versions --policy-arn $POLICY_ARN --query 'Versions[?!IsDefaultVersion].VersionId' --output text | \
    xargs -n1 -I{} aws iam delete-policy-version --policy-arn $POLICY_ARN --version-id {}

# Now delete the policy
aws iam delete-policy --policy-arn $POLICY_ARN

# Delete user
aws iam delete-user --user-name hedera-kms-user
```

---

## Quick Reference: All CLI Commands

```bash
# === AWS CLI Setup ===
aws configure
aws sts get-caller-identity

# === IAM User Creation ===
aws iam create-user --user-name hedera-kms-user
aws iam create-policy --policy-name HederaKMSSigningPolicy --policy-document file://hedera-kms-policy.json
aws iam attach-user-policy --user-name hedera-kms-user --policy-arn arn:aws:iam::ACCOUNT:policy/HederaKMSSigningPolicy
aws iam create-access-key --user-name hedera-kms-user

# === KMS Key Creation ===
aws kms create-key --key-spec ECC_SECG_P256K1 --key-usage SIGN_VERIFY --description "Hedera Signing"
aws kms create-alias --alias-name alias/hedera-signing-key --target-key-id KEY_ID
aws kms get-public-key --key-id KEY_ID

# === Verification ===
aws kms describe-key --key-id KEY_ID
aws kms list-keys
aws iam list-attached-user-policies --user-name hedera-kms-user
```

---

## Resources

- [AWS KMS Documentation](https://docs.aws.amazon.com/kms/)
- [Hedera SDK Documentation](https://docs.hedera.com/hedera/sdks-and-apis/sdks)
- [Hedera Developer Portal](https://portal.hedera.com/)
- [HashScan Explorer](https://hashscan.io/)
- [AWS CLI Installation](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)
- [secp256k1 Curve Info](https://en.bitcoin.it/wiki/Secp256k1)
