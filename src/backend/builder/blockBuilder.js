const bs58 = require('bs58');
const crypto = require('crypto');

/**
 * Performs a double SHA256 hash on a buffer.
 * @param {Buffer} buffer - The data to hash
 * @returns {Buffer} The resulting 32-byte hash
 */
const sha256d = (buffer) => crypto.createHash('sha256').update(crypto.createHash('sha256').update(buffer).digest()).digest();

/**
 * Converts a number to a little-endian hex string of a given byte length.
 * @param {number} num - The number to convert
 * @param {number} byteLength - The desired length of the hex string in bytes (e.g., 4 for version/ntime)
 * @returns {string} The little-endian hex string
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
 * @param {string} hex - The hex string to swap
 * @returns {string} The byte-swapped hex string
 */
function reverseHex(hex) {
    if (typeof hex !== 'string' || hex.length % 2 !== 0) {
        return '';
    }
    return hex.match(/.{2}/g).reverse().join('');
}

/**
 * Encodes a number into a variable-length integer (VarInt) hex string.
 * @param {number} num - The number to encode
 * @returns {string} The VarInt hex string
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
 * Constructs a complete block hex from mining submission for DigiByte
 * @param {Object} currentJob - Block template from getblocktemplate
 * @param {Object} job - Mining submission parameters containing jobId, extranonce2, ntime, and nonce
 * @param {string} extranonce1 - Pool-assigned unique miner ID (hex)
 * @param {string} [versionBits] - Version bits from miner (optional, for ASICBOOST)
 * @param {Object} config - Configuration object with poolPayoutAddress
 * @returns {string} Complete block hex ready for submitblock
 */
function buildBlock(currentJob, job, extranonce1, versionBits, config) {
    try {
        console.log('Building block with parameters:', {
            height: currentJob.height,
            jobId: job.jobId,
            extranonce1,
            extranonce2: job.extranonce2,
            ntime: job.ntime,
            nonce: job.nonce,
            versionBits
        });

        // 1. Create the coinbase transaction
        const heightBuffer = Buffer.alloc(4);
        heightBuffer.writeUInt32LE(currentJob.height);
        const heightHex = heightBuffer.toString('hex');
        // Use fixed push opcode '04' for 4 bytes, matching server.js mining.notify
        const heightPushOp = '04'; 
        const coinbaseScriptHex = heightPushOp + heightHex + extranonce1 + job.extranonce2;

        // scriptPubKey: A standard P2PKH script sending the reward to the pool's address
        const decoded = bs58.decode(config.poolPayoutAddress);
        const pubKeyHash = decoded.slice(1, -4); // Remove version byte and checksum, keep as buffer
        const payoutScriptPubKey = '76a914' + pubKeyHash.toString('hex') + '88ac';

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
            toVarIntHex(payoutScriptPubKey.length / 2) + // Output 1: pool payout scriptPubKey length
            payoutScriptPubKey + // Output 1: pool payout scriptPubKey
            '0000000000000000' + // Output 2: witness commitment value (0 DGB)
            toVarIntHex((currentJob.default_witness_commitment?.length / 2 || 32) + 2) + // Output 2: witness commitment scriptPubKey length
            '6a24' + (currentJob.default_witness_commitment || '0000000000000000000000000000000000000000000000000000000000000000') + // Output 2: witness commitment
            '00000000'; // locktime

        const coinbaseTx = Buffer.from(coinbaseTxHex, 'hex');
        const coinbaseTxid = sha256d(coinbaseTx);

        // 2. Calculate the Merkle Root
        const txHashes = (currentJob.transactions || []).map(tx => Buffer.from(reverseHex(tx.hash), 'hex'));
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
        const merkleRoot = merkleHashes[0]; // Final root in little-endian Buffer format

        // 3. Construct the 80-byte block header
        const header = Buffer.alloc(80);
        
        // Use versionBits from miner if available (for ASICBOOST), otherwise use template version
        header.write(versionBits ? reverseHex(versionBits) : toLittleEndianHex(currentJob.version, 4), 0, 4, 'hex');
        header.write(reverseHex(currentJob.previousblockhash), 4, 32, 'hex');
        merkleRoot.copy(header, 36);
        header.write(job.ntime, 68, 4, 'hex'); // ntime from miner is already little-endian
        header.write(currentJob.bits, 72, 4, 'hex'); // bits from template is already little-endian  
        header.write(job.nonce, 76, 4, 'hex'); // nonce from miner is already little-endian

        // 4. Serialize the full block
        const allTransactions = [coinbaseTx, ...(currentJob.transactions || []).map(tx => Buffer.from(tx.data, 'hex'))];
        const txCount = toVarIntHex(allTransactions.length);
        
        const blockHex = Buffer.concat([
            header,
            Buffer.from(txCount, 'hex'),
            ...allTransactions
        ]).toString('hex');

        console.log('Block construction completed:', {
            headerLength: header.length,
            txCount: allTransactions.length,
            blockLength: blockHex.length / 2,
            merkleRoot: merkleRoot.toString('hex')
        });

        return blockHex;

    } catch (error) {
        console.error('Error building block:', error);
        throw error;
    }
}

module.exports = {
    buildBlock
};