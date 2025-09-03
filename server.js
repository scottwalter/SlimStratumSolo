// server.js

const net = require('net');
const http = require('http');
const bs58 = require('bs58');
const crypto = require('crypto');

// --- Configuration ---
const PROXY_PORT = 3333; // Port for miners to connect to
const DIGIBYTE_RPC_HOST = '192.168.7.149'; // Digibyte Core RPC host
const DIGIBYTE_RPC_PORT = 9002; // Digibyte Core RPC port (mainnet default) -- USING A TEST NET INSTANCE!

// --- IMPORTANT ---
// Use your RPC username and the ORIGINAL plain-text password you used to generate the rpcauth line.
// Example: If your username is 'digiuser' and password is 'supersecret', set it to 'digiuser:supersecret'.
const DIGIBYTE_RPCAUTH = 'digiuser:digipoolpass'; // CHANGE THIS
const POOL_PAYOUT_ADDRESS = 'DTQTDEjbdfUvDZvU1Kp7bKLuqVQTF2qqJ7'; // CHANGE THIS to your pool's payout address
// --- Global State ---
const connectedMiners = new Set();
const extranonce1 = crypto.randomBytes(4).toString('hex'); // 4-byte extranonce for this proxy session
let currentJob = null; // Stores the current block template from Digibyte Core
let isFetchingJob = false; // Flag to prevent concurrent getblocktemplate calls

console.log(`Starting Stratum Proxy for Digibyte Core v8.22.2...`);

/**
 * Calculates the difficulty from the compact 'bits' format.
 * @param {string} bitsHex The 'bits' value from the block template as a hex string.
 * @returns {number} The calculated difficulty.
 */
function difficultyFromBits(bitsHex) {
    const targetMax = 0x0000ffff * Math.pow(2, 208); // Difficulty 1 target
    const exponent = parseInt(bitsHex.substring(0, 2), 16);
    const mantissa = parseInt(bitsHex.substring(2, 8), 16);
    const target = mantissa * Math.pow(2, 8 * (exponent - 3));
    return targetMax / target;
}
// --- Digibyte Core RPC Client ---
/**
 * Makes an RPC call to the Digibyte Core server.
 * @param {string} method The RPC method to call (e.g., 'getblocktemplate', 'submitblock').
 * @param {Array} params An array of parameters for the RPC method.
 * @returns {Promise<any>} A promise that resolves with the RPC result or rejects with an error.
 */
function callDigibyteRPC(method, params = []) {
    return new Promise((resolve, reject) => {
        const postData = JSON.stringify({
            jsonrpc: '1.0',
            id: 'SlimStratumSolo-proxy',
            method: method,
            params: params,
        });

        console.log(`Sending RPC payload for method '${method}':`, postData);

        const auth = 'Basic ' + Buffer.from(DIGIBYTE_RPCAUTH).toString('base64');

        const options = {
            hostname: DIGIBYTE_RPC_HOST,
            port: DIGIBYTE_RPC_PORT,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(postData),
                'Authorization': auth,
            },
        };

        const req = http.request(options, (res) => {
            let rawData = '';
            res.on('data', (chunk) => {
                rawData += chunk;
            });
            res.on('end', () => {
                try {
                    if (!rawData) {
                        // The server closed the connection without sending data. This is often an auth failure.
                        throw new Error(`Empty response from RPC server. Check RPC credentials (rpcauth) and rpcallowip in digibyte.conf. Status: ${res.statusCode}`);
                    }
                    const parsedData = JSON.parse(rawData);
                    if (parsedData.error) {
                        reject(parsedData.error);
                    } else {
                        resolve(parsedData.result);
                    }
                } catch (e) {
                    reject(new Error(`Failed to parse RPC response: ${e.message} - ${rawData}`));
                }
            });
        });

        req.on('error', (e) => {
            reject(new Error(`RPC request error to Digibyte Core: ${e.message}`));
        });

        req.write(postData);
        req.end();
    });
}

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
 * Performs a double SHA256 hash on a buffer.
 * @param {Buffer} buffer The data to hash.
 * @returns {Buffer} The resulting 32-byte hash.
 */
const sha256d = (buffer) => crypto.createHash('sha256').update(crypto.createHash('sha256').update(buffer).digest()).digest();

// --- Stratum Server Logic ---

/**
 * Fetches a new block template from Digibyte Core and notifies all connected, authenticated miners.
 */
async function fetchAndNotifyNewJob() {
    if (isFetchingJob) {
        console.log('Job fetch already in progress, skipping.');
        return;
    }
    isFetchingJob = true;
    try {
        console.log('Fetching new block template from Digibyte Core...');
        // Digibyte Core requires the 'segwit' rule to be specified to get a valid block template.
        
        const template = await callDigibyteRPC('getblocktemplate', [{
            "mode": "template",
            "rules": ["segwit"], // Explicitly request segwit rules as required by the node.
            
        }]);
        console.log(`Template received: ${JSON.stringify(template)}`);
        if (!template) {
            console.error('Failed to get a valid block template. Check Digibyte Core. Template:', JSON.stringify(template));
            isFetchingJob = false;
            return;
        }

        currentJob = template;
        console.log(`New job received: block ${template.height} - prevhash ${template.previousblockhash}`);

        // Construct a simplified mining.notify for miners (Stratum V1-like)
        // Parameters: [job_id, prevhash, coinbase1, coinbase2, merkle_branches, version, nbits, ntime, clean_jobs]
        const jobId = currentJob.previousblockhash; // Using prevhash as job_id, common in V1
        const prevHash = currentJob.previousblockhash;
        const coinbase1 = '';
        const coinbase2 = '';
        const merkleBranches = [];
        const version = toLittleEndianHex(currentJob.version, 4); // Block version, byte-swapped
        const nBits = currentJob.bits; // Target difficulty in compact format
        const nTime = toLittleEndianHex(currentJob.curtime, 4); // Current block time, byte-swapped
        const cleanJobs = true; // Clear previous jobs

        const notifyMessage = JSON.stringify({
            id: null,
            method: 'mining.notify',
            params: [
                jobId,
                prevHash,
                coinbase1,
                coinbase2,
                merkleBranches,
                version,
                nBits,
                nTime,
                cleanJobs,
            ],
        }) + '\n';
        
        let notifiedCount = 0;
        connectedMiners.forEach(socket => {
            if (socket.authenticated) { // Only send to authorized miners
                socket.write(notifyMessage); // The message already has a newline
                notifiedCount++;
            }
        });
        console.log(`Notified ${notifiedCount} authenticated miners with new job.`);

    } catch (error) {
        console.error('Error fetching or notifying new job:', error);
    } finally {
        isFetchingJob = false; // Reset the flag whether it succeeded or failed
    }
}

// Periodically fetch new jobs (e.g., every 10 seconds)
setInterval(fetchAndNotifyNewJob, 10 * 1000);

// Create the TCP server for miners
const server = net.createServer((socket) => {
    console.log('Miner connected from:', socket.remoteAddress);
    connectedMiners.add(socket);
    socket.authenticated = false; // Miner is not authenticated by default
    let dataBuffer = ''; // Buffer for incomplete messages

    socket.on('data', async (data) => {
        dataBuffer += data.toString();
        let messageEnd;

        // Process newline-delimited JSON messages
        while ((messageEnd = dataBuffer.indexOf('\n')) !== -1) {
            const message = dataBuffer.substring(0, messageEnd);
            dataBuffer = dataBuffer.substring(messageEnd + 1);

            try {
                const request = JSON.parse(message);
                console.log(`Received from miner (${socket.remoteAddress}): ${request.method} - ${JSON.stringify(request.params)}`);

                switch (request.method) {
                    case 'mining.subscribe':
                        const subscribeResponse = JSON.stringify({
                            id: request.id,
                            result: [
                                [
                                    ['mining.set_difficulty', '1'], // Placeholder difficulty 1
                                    ['mining.notify', '1']
                                ],
                                extranonce1, // Session-wide extranonce1
                                4 // Extranonce2_size (4 bytes)
                            ],
                            error: null,
                        }) + '\n';
                        socket.write(subscribeResponse);
                        console.log(`Sent mining.subscribe response to ${socket.remoteAddress}.`);
                        break;

                    case 'mining.authorize':
                        const authorizeResponse = JSON.stringify({
                            id: request.id,
                            result: true, // Assuming success
                            error: null,
                        }) + '\n';
                        socket.write(authorizeResponse);
                        socket.authenticated = true; // Mark as authenticated
                        console.log(`Miner ${socket.remoteAddress} authorized.`);
                        break;

                    case 'mining.configure':
                        const configureResponse = JSON.stringify({
                            id: request.id,
                            result: {}, // Successful configuration with no specific extensions enabled.
                            error: null,
                        }) + '\n';
                        socket.write(configureResponse);
                        break;

                    case 'mining.extranonce.subscribe':
                        const extranonceSubscribeResponse = JSON.stringify({
                            id: request.id,
                            result: true, // Acknowledge success
                            error: null,
                        }) + '\n';
                        socket.write(extranonceSubscribeResponse);
                        break;

                    case 'mining.suggest_difficulty':
                        const suggestDifficultyResponse = JSON.stringify({
                            id: request.id,
                            result: true,
                            error: null,
                        }) + '\n';
                        socket.write(suggestDifficultyResponse);
                        break;

                    case 'mining.submit':
                        if (!socket.authenticated) {
                            console.warn(`Miner ${socket.remoteAddress} tried to submit without authorization.`);
                             const errorResponse = JSON.stringify({
                                jsonrpc: '1.0',
                                id: request.id,
                                result: null,
                                error: [24, 'Unauthorized', null],
                            }) + '\n';
                            socket.write(errorResponse);
                            break;
                        }

                        if (!currentJob) {
                            console.warn(`Miner ${socket.remoteAddress} submitted share but no current job available.`);
                            const errorResponse = JSON.stringify({
                                jsonrpc: '1.0',
                                id: request.id,
                                result: null,
                                error: [21, 'Job not found', null],
                            }) + '\n';
                            socket.write(errorResponse);
                            break;
                        }

                        // Extract submitted share data from miner
                        const [workerName, submittedJobId, extranonce2, ntimeHex, nonceHex, versionBits] = request.params;
                        console.log(`versionBits: ${versionBits}, Converted: ${difficultyFromBits(versionBits)}}`);
                        console.log(`currentJobBits: ${currentJob.bits}, Converted: ${difficultyFromBits(currentJob.bits)}}`);

                        if (submittedJobId !== currentJob.previousblockhash) {
                            console.warn(`Miner ${socket.remoteAddress} submitted share for outdated job: ${submittedJobId} vs current ${currentJob.previousblockhash}`);
                            const errorResponse = JSON.stringify({
                                jsonrpc: '1.0',
                                id: request.id,
                                result: false,
                                error: [22, 'Stale job', null],
                            }) + '\n';
                            socket.write(errorResponse);
                            break;
                        }

                        console.log(`Miner ${socket.remoteAddress} submitted a potential block solution! Reconstructing and submitting...`);

                        // --- Block Construction Logic ---

                        // 1. Create the coinbase transaction.
                        // This transaction is special and created by the pool. It includes the miner's reward.
                        const heightHex = toLittleEndianHex(currentJob.height, 4); // Block height for BIP34 compliance
                        const heightVarInt = toVarIntHex(Buffer.from(heightHex, 'hex').length);
                        // scriptSig: block height + coinbaseaux flags + extranonce1 (proxy) + extranonce2 (miner)
                        const coinbaseScriptHex = heightVarInt + heightHex + currentJob.coinbaseaux.flags + extranonce1 + extranonce2;

                        // scriptPubKey: A standard P2PKH script sending the reward to the pool's address.
                        const payoutScriptPubKey = '76a914' + bs58.decode(POOL_PAYOUT_ADDRESS).toString('hex').slice(2, -8) + '88ac';

                        const coinbaseTxHex = '01000000' + // version
                            '01' + // number of inputs
                            '0000000000000000000000000000000000000000000000000000000000000000' + // prevout hash (null)
                            'ffffffff' + // prevout index (max)
                            toVarIntHex(coinbaseScriptHex.length / 2) + coinbaseScriptHex + // scriptSig
                            'ffffffff' + // sequence
                            '01' + // number of outputs
                            toLittleEndianHex(currentJob.coinbasevalue, 8) + // output value (satoshi)
                            toVarIntHex(payoutScriptPubKey.length / 2) + // scriptPubKey length
                            payoutScriptPubKey +
                            '00000000'; // locktime

                        const coinbaseTx = Buffer.from(coinbaseTxHex, 'hex');
                        const coinbaseTxid = sha256d(coinbaseTx);

                        // 2. Calculate the Merkle Root.
                        // The transaction hashes from getblocktemplate are big-endian and must be reversed.
                        const txHashes = currentJob.transactions.map(tx => Buffer.from(reverseHex(tx.hash), 'hex'));
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
                        const merkleRoot = merkleHashes[0]; // This is the final root, already in little-endian Buffer format.

                        // 3. Construct the 80-byte block header.
                        const header = Buffer.alloc(80);
                        // Use versionBits from miner if available (for ASICBOOST), otherwise use template version.
                        // All these fields must be written in little-endian format.
                        header.write(versionBits ? reverseHex(versionBits) : toLittleEndianHex(currentJob.version, 4), 0, 4, 'hex');
                        header.write(reverseHex(currentJob.previousblockhash), 4, 32, 'hex');
                        merkleRoot.copy(header, 36);
                        header.write(reverseHex(ntimeHex), 68, 4, 'hex');
                        header.write(reverseHex(currentJob.bits), 72, 4, 'hex');
                        header.write(reverseHex(nonceHex), 76, 4, 'hex');

                        // 4. Serialize the full block.
                        const txCount = toVarIntHex(currentJob.transactions.length + 1);
                        const blockHex = Buffer.concat([
                            header,
                            Buffer.from(txCount, 'hex'),
                            coinbaseTx,
                            ...currentJob.transactions.map(tx => Buffer.from(tx.data, 'hex'))
                        ]).toString('hex');

                        // 5. Submit the block to the Digibyte Core node.
                        submitBlock(blockHex, request.id, socket);
                        break;

                    default:
                        console.warn(`Unknown mining method from ${socket.remoteAddress}: ${request.method}`);
                        const unknownResponse = JSON.stringify({
                            id: request.id,
                            result: null,
                            error: [20, `Unknown method: ${request.method}`, null],
                        }) + '\n';
                        socket.write(unknownResponse);
                        break;
                }

            } catch (e) {
                console.error(`Error parsing miner message from ${socket.remoteAddress}: ${e.message}. Raw data: '${message}'`);
                const parseErrorResponse = JSON.stringify({
                    jsonrpc: '1.0',
                    id: null,
                    error: {
                        code: -32700,
                        message: 'Parse error',
                    },
                }) + '\n';
                socket.write(parseErrorResponse);
            }
        }
    });

    socket.on('end', () => {
        console.log('Miner disconnected from:', socket.remoteAddress);
        connectedMiners.delete(socket);
    });

    socket.on('error', (err) => {
        console.error('Socket error from miner:', err.message, 'from:', socket.remoteAddress);
        connectedMiners.delete(socket);
    });
});

/**
 * Submits a fully constructed block hex to the Digibyte Core node and handles the response.
 * @param {string} blockHex The full, serialized block in hex format.
 * @param {string|number} requestId The JSON-RPC request ID from the miner's submission.
 * @param {net.Socket} socket The miner's socket connection.
 */
async function submitBlock(blockHex, requestId, socket) {
    try {
        const submissionResult = await callDigibyteRPC('submitblock', [blockHex]);
        if (submissionResult === null) {
            // A 'null' result from submitblock means the block was accepted.
            console.log('🎉🎉🎉 BLOCK FOUND AND ACCEPTED! 🎉🎉🎉');
            socket.write(JSON.stringify({ id: requestId, result: true, error: null }) + '\n');
            await fetchAndNotifyNewJob(); // Fetch a new job immediately to not waste hash power.
        } else {
            // The node returned an error string (e.g., "inconclusive", "duplicate", "high-hash").
            console.warn(`Block rejected by Digibyte Core: ${submissionResult}`);
            socket.write(JSON.stringify({ id: requestId, result: false, error: [22, `Block rejected: ${submissionResult}`, null] }) + '\n');
        }
    } catch (e) {
        console.error('Error submitting block to Digibyte Core:', e.message);
        socket.write(JSON.stringify({ id: requestId, result: false, error: [-32000, `RPC submission error: ${e.message}`, null] }) + '\n');
    }
}

server.listen(PROXY_PORT, () => {
    console.log(`Stratum proxy listening on port ${PROXY_PORT}`);
    console.log(`Proxying to Digibyte Core RPC at ${DIGIBYTE_RPC_HOST}:${DIGIBYTE_RPC_PORT}`);
    fetchAndNotifyNewJob();
});

// Handle graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM signal received: closing proxy server');
    server.close(() => {
        console.log('Proxy server closed');
        process.exit(0);
    });
});
process.on('SIGINT', () => {
    console.log('SIGINT signal received: closing proxy server');
    server.close(() => {
        console.log('Proxy server closed');
        process.exit(0);
    });
});
