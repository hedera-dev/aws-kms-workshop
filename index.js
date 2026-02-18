const { KMSClient, SignCommand, GetPublicKeyCommand } = require("@aws-sdk/client-kms");
const {
  Client,
  Hbar,
  AccountCreateTransaction,
  PublicKey,
  AccountBalanceQuery,
  TransferTransaction,
} = require("@hashgraph/sdk");
const elliptic = require("elliptic");
const keccak256 = require("keccak256");
const asn1 = require("asn1.js");
require("dotenv").config();

// Initialize KMS client
const kmsClient = new KMSClient({
  credentials: {
    accessKeyId: process.env.AWS_KMS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_KMS_SECRET_ACCESS_KEY,
  },
  region: process.env.AWS_KMS_REGION,
});

// ASN.1 parser for ECDSA signatures (KMS returns DER-encoded signatures)
const EcdsaSigAsnParse = asn1.define("EcdsaSig", function () {
  this.seq().obj(this.key("r").int(), this.key("s").int());
});

/**
 * Creates a KMS signer with its associated public key
 */
async function createKmsSigner(keyId) {
  // Get public key from KMS
  const response = await kmsClient.send(new GetPublicKeyCommand({ KeyId: keyId }));

  // Parse the public key (remove ASN.1 prefix for secp256k1)
  const ec = new elliptic.ec("secp256k1");
  let hexKey = Buffer.from(response.PublicKey).toString("hex");
  hexKey = hexKey.replace("3056301006072a8648ce3d020106052b8104000a034200", "");

  const ecKey = ec.keyFromPublic(hexKey, "hex");
  const publicKey = PublicKey.fromBytesECDSA(
    Buffer.from(ecKey.getPublic().encodeCompressed("hex"), "hex")
  );

  // Signer function for Hedera transactions
  const signer = async (message) => {
    // Hash with keccak256 (required for Hedera ECDSA)
    const hash = keccak256(Buffer.from(message));

    // Sign the hash with KMS
    const signResponse = await kmsClient.send(
      new SignCommand({
        KeyId: keyId,
        Message: hash,
        MessageType: "DIGEST",
        SigningAlgorithm: "ECDSA_SHA_256",
      })
    );

    // Parse DER signature to raw format (r || s)
    const decoded = EcdsaSigAsnParse.decode(Buffer.from(signResponse.Signature), "der");
    const signature = new Uint8Array(64);
    signature.set(decoded.r.toArray("be", 32), 0);
    signature.set(decoded.s.toArray("be", 32), 32);

    return signature;
  };

  return { publicKey, signer };
}

async function main() {
  // Create KMS signer
  const { publicKey, signer } = await createKmsSigner(process.env.AWS_KMS_KEY_ID);
  console.log("KMS Public Key:", publicKey.toStringRaw());

  // Setup operator client (pays for account creation)
  const operatorClient = Client.forTestnet();
  operatorClient.setOperator(process.env.HEDERA_ACCOUNT_ID, process.env.HEDERA_PRIVATE_KEY);

  // Create new account with KMS public key
  const createTx = await new AccountCreateTransaction()
    .setKey(publicKey)
    .setInitialBalance(Hbar.fromTinybars(200000))
    .execute(operatorClient);

  const receipt = await createTx.getReceipt(operatorClient);
  const newAccountId = receipt.accountId;
  console.log("New account ID:", newAccountId.toString());

  // Check balance
  const balance = await new AccountBalanceQuery()
    .setAccountId(newAccountId)
    .execute(operatorClient);
  console.log("Account balance:", balance.hbars.toString());

  // Setup client for KMS-signed transactions
  const kmsSignedClient = Client.forTestnet();
  kmsSignedClient.setOperatorWith(newAccountId, publicKey, signer);

  // Transfer HBAR using KMS signature
  const transferTx = await new TransferTransaction()
    .addHbarTransfer(newAccountId, Hbar.fromTinybars(-10000))
    .addHbarTransfer("0.0.3", Hbar.fromTinybars(10000))
    .execute(kmsSignedClient);

  const transferReceipt = await transferTx.getReceipt(kmsSignedClient);
  console.log("Transfer status:", transferReceipt.status.toString());

  // Link to transaction on HashScan
  const txId = transferTx.transactionId
    .toString()
    .replace("@", "-")
    .replace(/\./g, "-")
    .replace(/0-/g, "0.");
  console.log("HashScan: https://hashscan.io/testnet/transaction/" + txId);
}

main().catch(console.error);
