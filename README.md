# Hedera + AWS KMS Signing Workshop

Sign Hedera transactions using AWS Key Management Service (KMS). Private keys stay secure in AWS - you only receive signatures.

## Quick Start

See [WORKSHOP.md](./WORKSHOP.md) for the full step-by-step guide.

```bash
git clone https://github.com/hedera-dev/aws-kms-workshop.git
cd aws-kms-workshop
npm install
# Follow WORKSHOP.md to configure AWS KMS and .env
npm start
```

## Prerequisites

- AWS Account with KMS access
- Node.js 18+
- Hedera Testnet Account ([portal.hedera.com](https://portal.hedera.com/))

## Why KMS?

- Private keys **never** leave AWS infrastructure
- Tamper-resistant hardware security modules (HSMs)
- Audit logs and access controls built-in
- Key rotation capabilities

## License

Apache-2.0
