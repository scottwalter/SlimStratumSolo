// server.js

const net = require('node:net');
const rpcServices = require('./src/backend/controller/rpcServices');
const submitBlockBuilder = require('./src/backend/builder/submitBlockBuilder');
const getBlockTemplateBuilder = require('./src/backend/builder/blockTemplateBuilder');
const verifyShares = require('./src/backend/utils/verifyShares');
const bs58 = require('bs58');
const crypto = require('crypto');

// --- Configuration ---
const proxyPort = 3333; // Port for miners to connect to
const rpcHost = '192.168.7.149'; // Digibyte Core RPC host
const rpcPort = 9001; // Digibyte Core RPC port (mainnet default) -- USING A TEST NET INSTANCE!
const rpcAuth = 'digiuser:digipoolpass'; // CHANGE THIS
const poolPayoutAddress = 'DTQTDEjbdfUvDZvU1Kp7bKLuqVQTF2qqJ7'; // CHANGE THIS to your pool's payout address
const defaultDifficulty = 1000; //Set the minimum difficulty level for miners
//Create a config object to pass around for use
const config = {
    "proxyPort":proxyPort,
    "rpcHost":rpcHost,
    "rpcPort":rpcPort,
    "rpcAuth":rpcAuth,
    "poolPayoutAddress":poolPayoutAddress,
    "defaultDifficulty":defaultDifficulty,

}

// --- Global State ---
const connectedMiners = new Set();
const extranonce1 = crypto.randomBytes(4).toString('hex'); // 4-byte extranonce for this proxy session
let currentJob = null; // Stores the current block template from Digibyte Core
let isFetchingJob = false; // Flag to prevent concurrent getblocktemplate calls

console.log(`Starting Slim Stratum Solo Proxy...`);


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
    //Boolean to decide if we notify or not based on fetched template
    let isNewBlock = true;
    

    try {
        let currentHeight = 0 ; //set to zero in case it is a first run.
        //If there is a currentJob, set the currentHeight to it
        if(currentJob){
            currentHeight = currentJob.height;
        }
        //Fetch the block
        console.log('Fetching new block template from Crypto Node...');
        
        // Digibyte Core requires the 'segwit' rule to be specified to get a valid block template.
        const template = await getBlockTemplateBuilder.getBlockTemplate(config);
       console.log(`Template received: ${JSON.stringify(template)}`);
        
        // Construct coinbase1 and coinbase2 for mining.notify
        const heightBuffer = Buffer.alloc(4);
        heightBuffer.writeUInt32LE(template.height);
        const heightHexLE = heightBuffer.toString('hex'); // Little-endian hex of height
        const heightPushOp = '04'; // Opcode for pushing 4 bytes of data

        // coinbase1: Prefix of the coinbase scriptSig (height + extranonce1)
        const coinbase1 = heightPushOp + heightHexLE + extranonce1;
        // coinbase2: Suffix of the coinbase scriptSig (empty for now, as no flags from template)
        const coinbase2 = '';
        if (!template) {
            console.error('Failed to get a valid block template. Check Digibyte Core. Template:', JSON.stringify(template));
            isFetchingJob = false;
            return;
        }   
        //See if we have a new block in the tempalte
        if(currentHeight !== template.height){
            //We have a new block, so swap the currentJob and set the notify flag to true;
            currentJob = template;
            console.log(`New job received: block ${template.height} - prevhash ${template.previousblockhash}`);
        }else{
            //Block is not new so no need to notify any miners
            isNewBlock=false;
            console.log(`curentJob is the current block height, so not notifying any miners.`);
        }
        if(isNewBlock){ //We have a new block, so notify miners to clean_jobs and start crunching on this block
            // Construct a simplified mining.notify for miners (Stratum V1-like)
            // Parameters: [job_id, prevhash, coinbase1, coinbase2, merkle_branches, version, nbits, ntime, clean_jobs]
            const jobId = currentJob.previousblockhash; // Using prevhash as job_id, common in V1
            const prevHash = currentJob.previousblockhash;
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
        }
        

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
                                    ['mining.set_difficulty', '1000'], // Placeholder difficulty 1
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
                        const [workerName, submittedJobId, extranonce2, ntimeHex, nonceHex, versionBits] = request.params;
                        
                        
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
                        //See if we should even try to submit this block, has to be equal of greater than the currentJobBits
                        let job = {
                            jobId: submittedJobId,
                            extranonce2: extranonce2,
                            ntime: ntimeHex,
                            nonce: nonceHex,
                        }
                        let Verify = verifyShares.verifyShare(currentJob, job, extranonce1, config.defaultDifficulty);
                        let meetsShareTarget = verify.meetsShareTarget;
                        let meetsNetworkTarget = verify.meetsNetworkTarget;
                        if(meetsNetworkTarget){ // worthy of submission to the node
                            console.log(`Miner ${socket.remoteAddress} submitted a potential block solution! Reconstructing and submitting...`);

                            // --- Block Construction Logic ---

                            // 1. Create the coinbase transaction.
                            // This transaction is special and created by the pool. It includes the miner's reward.
                            const heightBuffer = Buffer.alloc(4);
                            heightBuffer.writeUInt32LE(currentJob.height);
                            const heightHex = heightBuffer.toString('hex');
                            const heightVarInt = toVarIntHex(heightBuffer.length); // Correctly get length from the buffer
                            const coinbaseScriptHex = heightVarInt + heightHex + extranonce1 + extranonce2;

                            // scriptPubKey: A standard P2PKH script sending the reward to the pool's address.
                            const payoutScriptPubKey = '76a914' + bs58.decode(config.poolPayoutAddress).toString('hex').slice(2, -8) + '88ac';

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
                                toVarIntHex((currentJob.default_witness_commitment.length / 2) + 2) + // Output 2: witness commitment scriptPubKey length (0x6a + 0x24 + 36 bytes)
                                '6a24' + currentJob.default_witness_commitment + // Output 2: witness commitment scriptPubKey (OP_RETURN + PUSH_36 + commitment)
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
                            header.write(versionBits ? reverseHex(versionBits) : toLittleEndianHex(currentJob.version, 4), 0, 4, 'hex'); // versionBits is big-endian, template version is a number
                            header.write(reverseHex(currentJob.previousblockhash), 4, 32, 'hex');
                            merkleRoot.copy(header, 36);
                            header.write(ntimeHex, 68, 4, 'hex'); // ntime from miner is already little-endian
                            header.write(currentJob.bits, 72, 4, 'hex'); // bits from template is already little-endian
                            header.write(nonceHex, 76, 4, 'hex'); // nonce from miner is already little-endian

                            // 4. Serialize the full block.
                            const txCount = toVarIntHex(1); // Only coinbase transaction
                            const blockHex = Buffer.concat([ // This was the line with the issue.
                                header,
                                Buffer.from(txCount, 'hex'),
                                coinbaseTx,
                                ...currentJob.transactions.map(tx => Buffer.from(tx.data, 'hex'))
                            ]).toString('hex'); // Correctly concatenate all parts of the block.

                            // 5. Submit the block to the Digibyte Core node.
                            console.log(`Would have sent this to submitBlock: ${blockHex},${request.id},${socket.remoteAddress}`);
                            submitBlock(blockHex, request.id, socket);
                            break;
                        }
                        if(meetsShareTarget){ //Worthy of a share for POW
                            //Send back a message saying we accepted the share, even though it wasn't worthy of a new block
                            socket.write(JSON.stringify({ id: request.id, result: true, error: null }) + '\n');
                            console.log(`was a good POW share but not worthy of submitting as a block, so didn't bother to submit to node.`);
                            break;
                        }
                        //End of submit section
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

/**
 * Submits a fully constructed block hex to the Digibyte Core node and handles the response.
 * @param {string} blockHex The full, serialized block in hex format.
 * @param {string|number} requestId The JSON-RPC request ID from the miner's submission.
 * @param {net.Socket} socket The miner's socket connection.
 */
async function submitBlock(blockHex, requestId, socket) {
    try {
        const submissionResult = await rpcServices.callRPCService('submitblock', [blockHex]);
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

server.listen(config.proxyPort, () => {
    console.log(`Stratum proxy listening on port ${config.proxyPort}`);
    console.log(`Proxying to Digibyte Core RPC at ${config.rpcHost}:${config.rpcPort}`);
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
