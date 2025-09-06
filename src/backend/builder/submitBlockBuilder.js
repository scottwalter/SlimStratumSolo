// submitblock_builder.js
const crypto = require('crypto');
const rpcServices = require('../controller/rpcServices');

/**
 * Builds a hex-encoded raw block suitable for submitblock RPC call
 * @param {Object} gbt - The getblocktemplate JSON object from DigiByte Core
 * @param {string} payoutScriptPubKeyHex - Hex scriptPubKey for the pool payout address 
 * @param {Object} [opts={}] - Optional parameters
 * @param {number} [opts.txVersion=2] - Coinbase transaction version
 * @param {number} [opts.lockTime=0] - Coinbase locktime
 * @param {Buffer|string} [opts.extraNonce=Buffer.alloc(0)] - Extra nonce embedded in coinbase scriptSig
 * @returns {string} Complete raw block hex ready for submitblock
 */
function buildSubmitBlockHex(gbt, payoutScriptPubKeyHex, opts = {}) {
  const txVersion = opts.txVersion ?? 2;
  const lockTime = opts.lockTime ?? 0;
  const extraNonceBuf = toBuffer(opts.extraNonce ?? Buffer.alloc(0));

  // --- Helpers ---
  function toBuffer(x) {
    if (Buffer.isBuffer(x)) return x;
    if (typeof x === 'string') {
      if (x.startsWith('0x')) return Buffer.from(x.slice(2), 'hex');
      return Buffer.from(x, 'hex');
    }
    throw new Error('toBuffer: provide Buffer or hex string');
  }
  const u32LE = (n) => {
    const b = Buffer.allocUnsafe(4);
    b.writeUInt32LE(n >>> 0);
    return b;
  };
  const i32LE = (n) => {
    const b = Buffer.allocUnsafe(4);
    b.writeInt32LE(n | 0);
    return b;
  };
  const u64LE = (bn) => {
    // bn: BigInt or number
    let v = typeof bn === 'bigint' ? bn : BigInt(bn);
    const b = Buffer.allocUnsafe(8);
    b.writeUInt32LE(Number(v & 0xffffffffn), 0);
    b.writeUInt32LE(Number((v >> 32n) & 0xffffffffn), 4);
    return b;
  };
  const varInt = (n) => {
    if (n < 0xfd) return Buffer.from([n]);
    if (n <= 0xffff) {
      const b = Buffer.allocUnsafe(3);
      b[0] = 0xfd;
      b.writeUInt16LE(n, 1);
      return b;
    }
    if (n <= 0xffffffff) {
      const b = Buffer.allocUnsafe(5);
      b[0] = 0xfe;
      b.writeUInt32LE(n >>> 0, 1);
      return b;
    }
    const b = Buffer.allocUnsafe(9);
    b[0] = 0xff;
    // write BigInt
    b.writeUInt32LE(Number(BigInt(n) & 0xffffffffn), 1);
    b.writeUInt32LE(Number((BigInt(n) >> 32n) & 0xffffffffn), 5);
    return b;
  };
  const dsha256 = (buf) =>
    crypto.createHash('sha256').update(crypto.createHash('sha256').update(buf).digest()).digest();

  const hexToLE32 = (hex) => Buffer.from(hex, 'hex').reverse(); // 32-byte hash hex -> LE

  // --- 1) Build coinbase scriptSig (BIP34 height push + optional extranonce + template tag) ---
  // BIP34: push(height as little-endian minimal)
  function encodeBip34Height(height) {
    // Minimal little-endian number (no sign, remove leading 0x00 unless needed)
    let h = height;
    const bytes = [];
    while (h > 0) {
      bytes.push(h & 0xff);
      h = Math.floor(h / 256);
    }
    if (bytes.length === 0) bytes.push(0x00);
    // Minimal-encoding rule doesn't require sign byte for positive numbers.
    return Buffer.from([bytes.length, ...bytes]);
  }

  const heightPush = encodeBip34Height(gbt.height);
  const coinbaseTag = Buffer.from('2f6e6f64652d756e642f', 'hex'); // "/node-und/" (arbitrary; feel free to change)
  const scriptSig = Buffer.concat([
    heightPush,
    Buffer.from([extraNonceBuf.length]),
    extraNonceBuf,
    Buffer.from([coinbaseTag.length]),
    coinbaseTag
  ]);
  const scriptSigLen = varInt(scriptSig.length);

  // --- 2) Build coinbase outputs ---
  const outputs = [];

  // (a) Spendable miner output: value = coinbasevalue (since no tx fees in template)
  const valueMiner = u64LE(BigInt(gbt.coinbasevalue)); // satoshis (DigiByte uses 1e8 base as well)
  const minerScript = toBuffer(payoutScriptPubKeyHex);
  outputs.push(Buffer.concat([valueMiner, varInt(minerScript.length), minerScript]));

  // (b) Optional default witness commitment (OP_RETURN) from template, zero value
  if (gbt.default_witness_commitment) {
    const commitScript = Buffer.from(gbt.default_witness_commitment, 'hex');
    outputs.push(Buffer.concat([u64LE(0n), varInt(commitScript.length), commitScript]));
  }

  const voutCnt = varInt(outputs.length);

  // --- 3) Serialize coinbase transaction (NON-SegWit path: no marker/flag, no witness) ---
  const txInPrevout = Buffer.concat([
    Buffer.alloc(32, 0x00),       // prev tx hash (all zero)
    Buffer.from('ffffffff', 'hex') // prev index = 0xffffffff
  ]);
  const sequence = Buffer.from('ffffffff', 'hex');

  const tx = Buffer.concat([
    i32LE(txVersion),
    varInt(1),                    // 1 input (coinbase)
    txInPrevout,
    scriptSigLen,
    scriptSig,
    sequence,
    voutCnt,
    ...outputs,
    u32LE(lockTime)
  ]);

  const txid = dsha256(tx).reverse(); // LE for Merkle computations

  // --- 4) Merkle root (only coinbase, no transactions in template) ---
  const merkleRoot = txid; // single tx -> merkle = txid
  // If there were txs: reduce pairwise dsha256 of concat of LE hashes, duplicating odd last.

  // --- 5) Block header ---
  // version (LE int32)
  // prevhash (32 LE)
  // merkle root (32 LE)
  // time (LE u32)
  // bits (LE u32 from compact)
  // nonce (LE u32) -> set 0 for now
  const header = Buffer.concat([
    i32LE(gbt.version),
    hexToLE32(gbt.previousblockhash),
    merkleRoot,
    u32LE(gbt.curtime),
    Buffer.from(gbt.bits, 'hex').reverse(), // bits field as LE
    u32LE(0) // nonce placeholder
  ]);

  // --- 6) Final block = header + varint(tx_count) + transactions ---
  const block = Buffer.concat([header, varInt(1 /* tx count */), tx]);
  
  return block.toString('hex');
}

/**
 * Submits a fully constructed block hex to DigiByte Core and handles the response
 * @param {string} blockHex - The complete serialized block in hex format
 * @param {string|number} requestId - JSON-RPC request ID from miner's submission
 * @param {net.Socket} socket - The miner's socket connection
 * @param {Object} config - Configuration object with RPC settings
 * @returns {Promise<Object>} Object with success status and result details
 */
async function submitBlock(blockHex, requestId, socket, config) {
    try {
        const submissionResult = await rpcServices.callRPCService(config, 'submitblock', [blockHex]);
        if (submissionResult === null) {
            // A 'null' result from submitblock means the block was accepted.
            console.log('🎉🎉🎉 BLOCK FOUND AND ACCEPTED! 🎉🎉🎉');
            socket.write(JSON.stringify({ id: requestId, result: true, error: null }) + '\n');
            
            // Return success status so server.js can fetch new job
            return { success: true, result: submissionResult };
        } else {
            // The node returned an error string (e.g., "inconclusive", "duplicate", "high-hash").
            console.warn(`Block rejected by Digibyte Core: ${submissionResult}`);
            socket.write(JSON.stringify({ id: requestId, result: false, error: [22, `Block rejected: ${submissionResult}`, null] }) + '\n');
            
            return { success: false, result: submissionResult };
        }
    } catch (e) {
        console.error('Error submitting block to Digibyte Core:', e.message);
        socket.write(JSON.stringify({ id: requestId, result: false, error: [-32000, `RPC submission error: ${e.message}`, null] }) + '\n');
        
        return { success: false, error: e.message };
    }
}

module.exports = { buildSubmitBlockHex, submitBlock };
