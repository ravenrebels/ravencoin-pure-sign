const secp256k1 = require("secp256k1");
const crypto = require("crypto");
const wif = require("wif");

function doubleSha256(buffer) {
  return crypto.createHash("sha256").update(
    crypto.createHash("sha256").update(buffer).digest()
  ).digest();
}

function signRavencoinTransaction(data) {
  const { rawUnsignedTransaction, inputs, privateKeys, rvnUTXOs, assetUTXOs } = data;

  console.log("Unsigned Transaction:", rawUnsignedTransaction);

  // Parse the unsigned transaction
  let unsignedTx = Buffer.from(rawUnsignedTransaction, "hex");

  inputs.forEach((input, index) => {
    const utxo = [...rvnUTXOs, ...assetUTXOs].find(
      (utxo) => utxo.txid === input.txid && utxo.outputIndex === input.vout
    );

    if (!utxo) {
      throw new Error(`UTXO not found for input ${input.txid}:${input.vout}`);
    }

    console.log(`Processing input ${index} for TXID: ${input.txid} and VOUT: ${input.vout}`);

    // Create the preimage for the current input
    const preimage = createPreimage(unsignedTx, index, utxo.script, utxo.satoshis);
    console.log(`Preimage for input ${index}:`, preimage.toString("hex"));

    // Hash the preimage
    const hash = doubleSha256(preimage);
    console.log(`Hash for input ${index}:`, hash.toString("hex"));

    // Get the private key
    const privateKeyWIF = privateKeys[input.address];
    if (!privateKeyWIF) {
      throw new Error(`Private key not found for address: ${input.address}`);
    }
    const privateKey = wif.decode(privateKeyWIF).privateKey;

    // Sign the hash
    const { signature } = secp256k1.ecdsaSign(hash, privateKey);
    const publicKey = secp256k1.publicKeyCreate(privateKey, true);

    console.log(`Public Key for input ${index}:`, publicKey.toString("hex"));

    // Create the scriptSig
    const scriptSig = createScriptSig(signature, publicKey);
    console.log(`ScriptSig for input ${index}:`, scriptSig.toString("hex"));

    // Update the transaction buffer
    unsignedTx = attachScriptSig(unsignedTx, index, scriptSig);
    console.log(`Transaction after attaching ScriptSig for input ${index}:`, unsignedTx.toString("hex"));
  });

  console.log("Final Signed Transaction:", unsignedTx.toString("hex"));
  return unsignedTx.toString("hex");
}

function createPreimage(tx, inputIndex, scriptPubKey, amount) {
  // Serialize the transaction preimage for the specific input
  const inputBuffer = Buffer.from(tx);
  const inputStart = locateInputStart(inputBuffer, inputIndex);

  const scriptBuffer = Buffer.from(scriptPubKey, "hex");
  inputBuffer[inputStart] = scriptBuffer.length;
  scriptBuffer.copy(inputBuffer, inputStart + 1);

  return Buffer.concat([inputBuffer, Buffer.from([0x01])]); // Append SIGHASH_ALL
}

function locateInputStart(tx, inputIndex) {
  let offset = 4; // Skip version
  offset += 1; // Input count

  for (let i = 0; i < inputIndex; i++) {
    offset += 36; // TXID (32 bytes) + VOUT (4 bytes)
    offset += tx[offset] + 1; // Script length + script
    offset += 4; // Sequence
  }

  return offset + 36; // Current input's scriptPubKey start
}

function createScriptSig(signature, publicKey) {
  const derSignature = Buffer.from(secp256k1.signatureExport(signature));
  const sigWithHashType = Buffer.concat([derSignature, Buffer.from([0x01])]); // Append SIGHASH_ALL

  return Buffer.concat([
    Buffer.from([sigWithHashType.length]), // Length of signature
    sigWithHashType,
    Buffer.from([publicKey.length]), // Length of public key
    publicKey,
  ]);
}

function attachScriptSig(tx, inputIndex, scriptSig) {
  const inputStart = locateInputStart(tx, inputIndex);

  // Slice the transaction buffer into sections
  const before = tx.slice(0, inputStart);
  const after = tx.slice(inputStart + tx[inputStart] + 1 + 4); // Skip old script and sequence

  // Build the new input section
  const scriptSigLength = scriptSig.length;
  const newInput = Buffer.concat([
    Buffer.from([scriptSigLength]), // ScriptSig length
    scriptSig,
    tx.slice(inputStart + 1 + tx[inputStart], inputStart + 1 + tx[inputStart] + 4), // Sequence
  ]);

  return Buffer.concat([before, newInput, after]);
}

function decodeTransaction(rawTx) {
  try {
    const tx = Buffer.from(rawTx, "hex");
    console.log("Transaction Decoded Successfully");
    console.log(tx.toString("hex"));
  } catch (err) {
    console.error("Transaction decode failed:", err.message);
  }
}

module.exports = { signRavencoinTransaction, decodeTransaction };
