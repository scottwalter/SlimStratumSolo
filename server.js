// server.js

const net = require('net');
const http = require('http');
const crypto = require('crypto');

// --- Configuration ---
const PROXY_PORT = 3333; // Port for miners to connect to
const DIGIBYTE_RPC_HOST = '192.168.7.149'; // Digibyte Core RPC host
const DIGIBYTE_RPC_PORT = 9001; // Digibyte Core RPC port (mainnet default)

// --- IMPORTANT ---
// Use your RPC username and the ORIGINAL plain-text password you used to generate the rpcauth line.
// Example: If your username is 'digiuser' and password is 'supersecret', set it to 'digiuser:supersecret'.
const DIGIBYTE_RPCAUTH = 'digiuser:digipoolpass'; // CHANGE THIS
// --- Global State ---
const connectedMiners = new Set();
const extranonce1 = crypto.randomBytes(4).toString('hex'); // 4-byte extranonce for this proxy session
let currentJob = null; // Stores the current block template from Digibyte Core
let isFetchingJob = false; // Flag to prevent concurrent getblocktemplate calls

console.log(`Starting Stratum Proxy for Digibyte Core v8.22.2...`);

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
            id: 'goose-proxy',
            method: method,
            params: params,
        });

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
        // We also request 'coinbasetxn' to get a coinbase transaction template.
        const template = await callDigibyteRPC('getblocktemplate', [{
            "mode": "template",
            "rules": ["segwit"] // Explicitly request segwit rules as required by the node.
        }]);
        
        if (!template || !template.coinbasetxn) {
            console.error('Failed to get a valid block template with coinbasetxn. Check Digibyte Core. Template:', JSON.stringify(template));
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
                                jsonrpc: '2.0',
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
                                jsonrpc: '2.0',
                                id: request.id,
                                result: null,
                                error: [21, 'Job not found', null],
                            }) + '\n';
                            socket.write(errorResponse);
                            break;
                        }

                        // Extract submitted share data from miner
                        const [workerName, submittedJobId, extranonce2, ntimeHex, nonceHex] = request.params;

                        if (submittedJobId !== currentJob.previousblockhash) {
                            console.warn(`Miner ${socket.remoteAddress} submitted share for outdated job: ${submittedJobId} vs current ${currentJob.previousblockhash}`);
                            const errorResponse = JSON.stringify({
                                jsonrpc: '2.0',
                                id: request.id,
                                result: false,
                                error: [22, 'Stale job', null],
                            }) + '\n';
                            socket.write(errorResponse);
                            break;
                        }

                        console.log(`Miner ${socket.remoteAddress} submitted a potential block solution! Reconstructing and submitting...`);

                        // 1. Reconstruct the coinbase transaction
                        const coinbaseTxTemplate = Buffer.from(currentJob.coinbasetxn.data, 'hex');
                        const extranonce = extranonce1 + extranonce2;
                        const coinbaseScript = Buffer.from(currentJob.coinbasetxn.coinbase_script, 'hex');
                        
                        const finalCoinbaseScript = Buffer.concat([coinbaseScript, Buffer.from(extranonce, 'hex')]);
                        
                        const scriptSigSizeOffset = currentJob.coinbasetxn.script_sig_size_offset;
                        const scriptSigOffset = currentJob.coinbasetxn.script_sig_offset;

                        const finalCoinbaseTx = Buffer.concat([
                            coinbaseTxTemplate.slice(0, scriptSigSizeOffset),
                            Buffer.from([finalCoinbaseScript.length]),
                            finalCoinbaseScript,
                            coinbaseTxTemplate.slice(scriptSigOffset + coinbaseScript.length)
                        ]);

                        const coinbaseTxid = sha256d(finalCoinbaseTx);

                        // 2. Re-calculate the Merkle Root
                        let merkleHashes = [coinbaseTxid, ...currentJob.transactions.map(tx => Buffer.from(tx.hash, 'hex'))];
                        while (merkleHashes.length > 1) {
                            if (merkleHashes.length % 2 !== 0) {
                                merkleHashes.push(merkleHashes[merkleHashes.length - 1]);
                            }
                            const nextLevel = [];
                            for (let i = 0; i < merkleHashes.length; i += 2) {
                                const combined = Buffer.concat([merkleHashes[i], merkleHashes[i + 1]]);
                                nextLevel.push(sha256d(combined));
                            }
                            merkleHashes = nextLevel;
                        }
                        const merkleRoot = merkleHashes[0];

                        // 3. Construct the block header
                        const header = Buffer.alloc(80);
                        header.writeInt32LE(currentJob.version, 0);
                        header.write(reverseHex(currentJob.previousblockhash), 4, 32, 'hex');
                        merkleRoot.copy(header, 36);
                        header.write(reverseHex(ntimeHex), 68, 4, 'hex');
                        header.write(reverseHex(currentJob.bits), 72, 4, 'hex');
                        header.write(reverseHex(nonceHex), 76, 4, 'hex');

                        // 4. Serialize the full block
                        const varIntTransactions = Buffer.from([currentJob.transactions.length + 1]);
                        const blockHex = Buffer.concat([
                            header,
                            varIntTransactions,
                            finalCoinbaseTx,
                            ...currentJob.transactions.map(tx => Buffer.from(tx.data, 'hex'))
                        ]).toString('hex');

                        // 5. Submit the block
                        try {
                            const submissionResult = await callDigibyteRPC('submitblock', [blockHex]);
                            if (submissionResult === null) {
                                console.log('🎉🎉🎉 BLOCK FOUND AND ACCEPTED! 🎉🎉🎉');
                                socket.write(JSON.stringify({ jsonrpc: '2.0', id: request.id, result: true, error: null }) + '\n');
                                await fetchAndNotifyNewJob(); // Fetch a new job immediately
                            } else {
                                console.warn(`Block rejected by Digibyte Core: ${submissionResult}`);
                                socket.write(JSON.stringify({ jsonrpc: '2.0', id: request.id, result: false, error: [22, `Block rejected: ${submissionResult}`, null] }) + '\n');
                            }
                        } catch (e) {
                            console.error('Error submitting block to Digibyte Core:', e);
                            socket.write(JSON.stringify({ jsonrpc: '2.0', id: request.id, result: false, error: [-32000, `RPC submission error: ${e.message}`, null] }) + '\n');
                        }
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
                    jsonrpc: '2.0',
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
