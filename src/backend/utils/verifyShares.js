const crypto = require('crypto');

/**
 * Performs a double SHA256 hash on a buffer.
 * @param {Buffer} buffer The data to hash.
 * @returns {Buffer} The resulting 32-byte hash.
 */
const sha256d = (buffer) => crypto.createHash('sha256').update(crypto.createHash('sha256').update(buffer).digest()).digest();

/**
 * Converts a number to a little-endian hex string of a given byte length.
 * @param {number} num The number to convert.
 * @param {number} byteLength The desired length of the hex string in bytes (e.g., 4 for version/ntime).
 * @returns {string} The little-endian hex string.
 */
function toLittleEndianHex(num, byteLength) {
    const hex = num.toString(16).padStart(byteLength * 2, '0');
    let littleEndianHex = '';
    for (let i = 0; i < byteLength; i++) {
        littleEndianHex += hex.substring((byteLength - 1 - i) * 2, (byteLength - i) * 2);
    }
    return littleEndianHex;
}

/**
 * Reverses the byte order of a hex string (little-endian to big-endian and vice-versa).
 * @param {string} hex The hex string to swap.
 * @returns {string} The byte-swapped hex string.
 */
function reverseHex(hex) {
    if (typeof hex !== 'string' || hex.length % 2 !== 0) {
        return '';
    }
    return hex.match(/.{2}/g).reverse().join('');
}

/**
 * Encodes a number into a variable-length integer (VarInt) hex string.
 * @param {number} num The number to encode.
 * @returns {string} The VarInt hex string.
 */
function toVarIntHex(num) {
    if (num < 0xfd) {
        return num.toString(16).padStart(2, '0');
    } else if (num <= 0xffff) {
        return 'fd' + toLittleEndianHex(num, 2);
    } else if (num <= 0xffffffff) {
        return 'fe' + toLittleEndianHex(num, 4);
    } else {
        // For BigInt, convert to 8-byte little-endian hex
        const buf = Buffer.alloc(8);
        buf.writeBigUInt64LE(BigInt(num));
        return 'ff' + buf.toString('hex');
    }
}

/**
 * Convert target from nBits (compact representation) to full 256-bit target
 * @param {string} nBits - The compact target representation as hex string
 * @returns {BigInt} - The full 256-bit target
 */
function nBitsToTarget(nBits) {
    const nBitsInt = parseInt(nBits, 16);
    const exponent = nBitsInt >>> 24;
    const coefficient = nBitsInt & 0xffffff;
    
    if (exponent <= 3) {
        return BigInt(coefficient >>> (8 * (3 - exponent)));
    } else {
        return BigInt(coefficient) << BigInt(8 * (exponent - 3));
    }
}

/**
 * Verifies a mining share submission and determines if it meets pool and network targets
 * @param {Object} currentJob - Block template from getblocktemplate
 * @param {Object} job - Mining submission parameters (jobId, extranonce2, ntime, nonce)
 * @param {string} extranonce1 - Pool-assigned unique miner ID (hex)
 * @param {number} poolDifficulty - Pool difficulty target
 * @returns {Object} - Verification results with meetsShareTarget and meetsNetworkTarget booleans
 */
async function verifyShare(currentJob, job, extranonce1, poolDifficulty = 1000) {
    try {
        // Build coinbase transaction for this share using EXACT same logic as server.js mining.notify
        const heightBuffer = Buffer.alloc(4);
        heightBuffer.writeUInt32LE(currentJob.height);
        const heightHexLE = heightBuffer.toString('hex'); // Little-endian hex of height

        // Construct coinbase scriptSig EXACTLY like server.js mining.notify does
        // server.js sends: heightPushOp + heightHexLE + extranonce1 (as coinbase1) + extranonce2 (miner appends)
        // Use fixed push opcode '04' for 4 bytes, NOT VarInt encoding
        const heightPushOp = '04'; // Fixed opcode for pushing exactly 4 bytes (matching mining.notify)
        const coinbaseScriptHex = heightPushOp + heightHexLE + extranonce1 + job.extranonce2;
        
        console.log('DEBUGGING: Coinbase verification construction:', {
            heightPushOp: heightPushOp,
            heightHexLE: heightHexLE, 
            extranonce1: extranonce1,
            extranonce2: job.extranonce2,
            finalCoinbaseScriptHex: coinbaseScriptHex,
            height: currentJob.height,
            scriptLength: coinbaseScriptHex.length / 2,
            expectedMinerConstruction: `coinbase1(${heightPushOp}${heightHexLE}${extranonce1}) + extranonce2(${job.extranonce2}) + coinbase2('')`
        });
        
        // Create coinbase transaction using EXACT same logic as blockBuilder.js
        const bs58 = require('bs58');
        
        // Use the actual payout address from config instead of placeholder
        const poolPayoutAddress = 'DTQTDEjbdfUvDZvU1Kp7bKLuqVQTF2qqJ7'; // From server.js config
        const decoded = bs58.decode(poolPayoutAddress);
        const pubKeyHash = decoded.slice(1, -4); // Remove version byte and checksum, keep as buffer
        const payoutScriptPubKey = '76a914' + Buffer.from(pubKeyHash).toString('hex') + '88ac';
        
        console.log('DEBUGGING: Address decoding details:', {
            poolPayoutAddress: poolPayoutAddress,
            decodedBuffer: decoded.toString('hex'),
            pubKeyHashBuffer: Buffer.from(pubKeyHash).toString('hex'), // Ensure proper hex conversion
            payoutScriptPubKey: payoutScriptPubKey,
            scriptLength: payoutScriptPubKey.length / 2
        });

        // Build coinbase transaction EXACTLY like blockBuilder.js does
        const coinbaseTxHex = toLittleEndianHex(currentJob.version, 4) + // version
            '00' + // SegWit marker (if version >= 0x20000000)
            '01' + // SegWit flag (if version >= 0x20000000) 
            '01' + // number of inputs
            '0000000000000000000000000000000000000000000000000000000000000000' + // prevout hash (null)
            'ffffffff' + // prevout index (max)
            toVarIntHex(coinbaseScriptHex.length / 2) + coinbaseScriptHex + // scriptSig
            'ffffffff' + // sequence
            '02' + // number of outputs (now 2: payout + witness commitment)
            toLittleEndianHex(currentJob.coinbasevalue, 8) + // Output 1: pool payout value
            toVarIntHex(25) + // Output 1: scriptPubKey length (25 bytes for P2PKH)
            payoutScriptPubKey + // Output 1: pool payout scriptPubKey
            '0000000000000000' + // Output 2: witness commitment value (0 DGB)
            toVarIntHex(38) + // Output 2: witness commitment scriptPubKey length (38 bytes: 0x6a + 0x24 + 36 bytes)  
            '6a24' + (currentJob.default_witness_commitment || '0000000000000000000000000000000000000000000000000000000000000000') + // Output 2: witness commitment scriptPubKey (OP_RETURN + PUSH_36 + commitment)
            '00000000'; // locktime

        const coinbaseTx = Buffer.from(coinbaseTxHex, 'hex');
        const coinbaseTxid = sha256d(coinbaseTx);
        
        console.log('DEBUGGING: Complete coinbase transaction:', {
            coinbaseTxHex: coinbaseTxHex,
            coinbaseTxLength: coinbaseTxHex.length / 2,
            coinbaseTxid: coinbaseTxid.toString('hex')
        });

        // Calculate merkle root
        // For solo mining with only coinbase tx, merkle root = coinbase txid
        const txHashes = currentJob.transactions?.map(tx => Buffer.from(reverseHex(tx.hash), 'hex')) || [];
        let merkleHashes = [coinbaseTxid, ...txHashes];

        while (merkleHashes.length > 1) {
            if (merkleHashes.length % 2 !== 0) {
                merkleHashes.push(merkleHashes[merkleHashes.length - 1]); // Duplicate last hash if odd number
            }
            const nextLevel = [];
            for (let i = 0; i < merkleHashes.length; i += 2) {
                const combined = Buffer.concat([merkleHashes[i], merkleHashes[i + 1]]);
                nextLevel.push(sha256d(combined));
            }
            merkleHashes = nextLevel;
        }
        const merkleRoot = merkleHashes[0];

        // Construct the 80-byte block header exactly as the miner would
        const header = Buffer.alloc(80);
        
        // Version (4 bytes, little-endian)
        header.writeUInt32LE(currentJob.version, 0);
        
        // Previous block hash (32 bytes, reversed from RPC format to little-endian)
        Buffer.from(currentJob.previousblockhash, 'hex').reverse().copy(header, 4);
        
        // Merkle root (32 bytes, already in little-endian format)
        merkleRoot.copy(header, 36);
        
        // Time from miner submission (4 bytes, already little-endian hex)
        Buffer.from(job.ntime, 'hex').copy(header, 68);
        
        // nBits (4 bytes, from template)
        Buffer.from(currentJob.bits, 'hex').copy(header, 72);
        
        // Nonce from miner (4 bytes, already little-endian hex)
        Buffer.from(job.nonce, 'hex').copy(header, 76);

        console.log('DEBUGGING: Block header construction details:', {
            headerHex: header.toString('hex'),
            headerLength: header.length,
            version: header.slice(0, 4).toString('hex'),
            prevBlockHash: header.slice(4, 36).toString('hex'),
            merkleRoot: header.slice(36, 68).toString('hex'),
            timestamp: header.slice(68, 72).toString('hex'),
            bits: header.slice(72, 76).toString('hex'),
            nonce: header.slice(76, 80).toString('hex')
        });

        // Calculate hash of the block header
        const blockHash = sha256d(header);
        
        console.log('DEBUGGING: Block hash calculation:', {
            blockHashLE: blockHash.toString('hex'),
            blockHashBE: Buffer.from(blockHash).reverse().toString('hex')
        });
        
        // Convert hash to big integer for comparison (reverse bytes for big-endian comparison)
        const hashHex = Buffer.from(blockHash).reverse().toString('hex');
        const hashInt = BigInt('0x' + hashHex);

        // Get network target from nBits
        const networkTarget = nBitsToTarget(currentJob.bits);
        
        // Calculate pool target (difficulty 1 target divided by pool difficulty)
        // DigiByte uses the same difficulty calculation as Bitcoin
        const diff1Target = BigInt('0x00000000FFFF0000000000000000000000000000000000000000000000000000');
        const poolTarget = diff1Target / BigInt(poolDifficulty);
        
        console.log('Target calculations:', {
            diff1Target: diff1Target.toString(16),
            poolDifficulty,
            poolTarget: poolTarget.toString(16),
            networkTarget: networkTarget.toString(16),
            hashInt: hashInt.toString(16)
        });

        const result = {
            hash: hashHex,
            hashInt: hashInt.toString(),
            networkTarget: networkTarget.toString(),
            poolTarget: poolTarget.toString(),
            meetsShareTarget: hashInt <= poolTarget,
            meetsNetworkTarget: hashInt <= networkTarget,
            difficulty: Number(diff1Target / hashInt)
        };

        return result;

    } catch (error) {
        console.error('Error verifying share:', error);
        return {
            hash: null,
            hashInt: null,
            networkTarget: null,
            poolTarget: null,
            meetsShareTarget: false,
            meetsNetworkTarget: false,
            error: error.message
        };
    }
}

module.exports = {
    verifyShare
};