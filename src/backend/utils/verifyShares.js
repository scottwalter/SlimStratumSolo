const crypto = require("crypto");

/**
 * Double SHA256
 */
function doubleSHA256(buffer) {
  return crypto.createHash("sha256")
    .update(crypto.createHash("sha256").update(buffer).digest())
    .digest();
}

/**
 * Convert nBits (compact target) to BigInt target
 */
function nBitsToTarget(nBits) {
  const exponent = Number((nBits >>> 24) & 0xff);
  const coefficient = nBits & 0xffffff;
  return BigInt(coefficient) << BigInt(8 * (exponent - 3));
}

/**
 * Build block header (80 bytes)
 * gbt = getblocktemplate JSON from node
 * job = mining.submit parameters (jobId, extranonce2, ntime, nonce)
 * extranonce1 = pool-assigned unique miner ID
 */
function buildBlockHeader(gbt, job, extranonce1) {
  // --- Step 1: coinbase & merkle root ---
  const coinbase = Buffer.concat([
    Buffer.from(gbt.coinbaseaux.flags, "hex"),
    Buffer.from(extranonce1, "hex"),
    Buffer.from(job.extranonce2, "hex"),
    Buffer.from(gbt.coinbasevalue.toString(16).padStart(16, "0"), "hex")
  ]);

  const coinbaseHash = doubleSHA256(coinbase);

  // Build merkle root from coinbase + merkle branches
  let merkleRoot = coinbaseHash;
  for (const branch of gbt.merklebranches) {
    merkleRoot = doubleSHA256(Buffer.concat([
      merkleRoot,
      Buffer.from(branch, "hex").reverse()
    ]));
  }

  // --- Step 2: assemble block header ---
  const header = Buffer.alloc(80);

  // version (4 bytes, LE)
  header.writeInt32LE(gbt.version, 0);

  // previous block hash (32 bytes, LE)
  Buffer.from(gbt.previousblockhash, "hex").reverse().copy(header, 4);

  // merkle root (32 bytes, LE)
  merkleRoot.reverse().copy(header, 36);

  // time (4 bytes, LE)
  header.writeUInt32LE(parseInt(job.ntime, 16), 68);

  // nBits (4 bytes, LE)
  header.writeUInt32LE(parseInt(gbt.bits, 16), 72);

  // nonce (4 bytes, LE)
  header.writeUInt32LE(parseInt(job.nonce, 16), 76);

  return header;
}

/**
 * Verify mining submission
 */
async function verifyShare(gbt, job, extranonce1, poolDifficulty = 1) {
  const header = buildBlockHeader(gbt, job, extranonce1);
  const hash = doubleSHA256(header);

  // Convert hash (LE) to BigInt
  const hashInt = BigInt("0x" + Buffer.from(hash).reverse().toString("hex"));

  // Network target from nBits
  const networkTarget = nBitsToTarget(parseInt(gbt.bits, 16));

  // Pool target (difficulty simplified to "diff 1" scaling)
  const diff1Target = nBitsToTarget(0x1d00ffff); // Bitcoin's max target
  const poolTarget = diff1Target / BigInt(poolDifficulty);

  return {
    hash: Buffer.from(hash).reverse().toString("hex"),
    hashInt: hashInt.toString(),
    meetsShareTarget: hashInt <= poolTarget,
    meetsNetworkTarget: hashInt <= networkTarget
  };
}

// ---------------------- Example Usage ----------------------

// Example GBT (simplified!)
const gbt = {
  version: 536870912,
  previousblockhash: "00000000000000000007d0f9284ed7b87a60fbd1b5a0f1f0b99e22eae6f5d7a2",
  coinbaseaux: { flags: "062f503253482f" },
  coinbasevalue: 625000000,
  merklebranches: [
    "4f3c...abcd" // <-- Normally dozens of these
  ],
  bits: "170fffff"
};

// Example mining.submit from a miner
const job = {
  jobId: "1",
  extranonce2: "00000001",
  ntime: "6502b4e1",
  nonce: "00000000"
};

const extranonce1 = "abcdef12"; // assigned by pool to miner

const result = verifyShare(gbt, job, extranonce1, 1024); // pool diff=1024
console.log(result);

module.exports = {
    verifyShare
}
    