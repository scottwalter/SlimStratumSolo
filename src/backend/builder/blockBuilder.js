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

        // 1. Create the coinbase transaction EXACTLY as sent in mining.notify
        // Reconstruct coinbase1 + extranonce1 + extranonce2 + coinbase2 format
        const heightBuffer = Buffer.alloc(4);
        heightBuffer.writeUInt32LE(currentJob.height);
        const heightHexLE = heightBuffer.toString('hex');
        const heightPushOp = '04';
        
        // Build coinbase1 exactly like server.js does
        const coinbase1 = [
            '01000000', // transaction version (1, little-endian)
            '01', // input count
            '00'.repeat(32), // null TXID
            'ffffffff', // null VOUT
            '23', // scriptSig length (35 bytes total)
            heightPushOp + heightHexLE // height push + height
        ].join('');
        
        // Build coinbase2 exactly like server.js does
        const decoded = bs58.decode(config.poolPayoutAddress);
        const pubKeyHash = decoded.slice(1, -4);
        const payoutScriptPubKey = '76a914' + Buffer.from(pubKeyHash).toString('hex') + '88ac';
        
        const coinbase2 = [
            '0f4d696e65642062792053636f74747900000000', // "Mined by Scott" + padding
            '02', // output count
            '0000000000000000', // witness commitment value
            '26', // scriptPubKey length
            '6a24' + (currentJob.default_witness_commitment || 'aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9'), // OP_RETURN + witness commitment
            toLittleEndianHex(currentJob.coinbasevalue, 8), // pool payout value
            '19', // scriptPubKey length
            payoutScriptPubKey, // pool payout scriptPubKey
            '00000000' // locktime
        ].join('');
        
        // Reconstruct complete coinbase transaction as miner would
        const completeCoinbaseTx = coinbase1 + extranonce1 + job.extranonce2 + coinbase2;
        console.log('Coinbase reconstruction:', {
            coinbase1: coinbase1,
            extranonce1: extranonce1,
            extranonce2: job.extranonce2,
            coinbase2: coinbase2,
            complete: completeCoinbaseTx
        });

        const coinbaseTx = Buffer.from(completeCoinbaseTx, 'hex');
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
        
        // Handle version bits from miner
        if (versionBits) {
            // versionBits from miner submission is the XOR result: rolled_version ^ template_version
            // We need to XOR it back with template version to get the actual rolled version
            const versionBitsInt = parseInt(versionBits, 16);
            const rolledVersion = versionBitsInt ^ currentJob.version;
            header.writeUInt32LE(rolledVersion, 0);
            console.log('Version calculation:', {
                templateVersion: '0x' + currentJob.version.toString(16),
                versionBitsFromMiner: versionBits,
                calculatedRolledVersion: '0x' + rolledVersion.toString(16)
            });
        } else {
            // Use template version as fallback
            header.writeUInt32LE(currentJob.version, 0);
        }
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