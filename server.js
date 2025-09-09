// server.js

const net = require('node:net');
const submitBlockBuilder = require('./src/backend/builder/submitBlockBuilder');
const getBlockTemplateBuilder = require('./src/backend/builder/blockTemplateBuilder');
const blockBuilder = require('./src/backend/builder/blockBuilder');
const verifyShares = require('./src/backend/utils/verifyShares');
const bs58 = require('bs58');
const crypto = require('crypto');

// --- Configuration ---
const proxyPort = 3333; // Port for miners to connect to
const rpcHost = '192.168.7.149'; // Digibyte Core RPC host
const rpcPort = 9001; // Digibyte Core RPC port (production)
const rpcAuth = 'digiuser:digipoolpass'; // CHANGE THIS
const poolPayoutAddress = 'DTQTDEjbdfUvDZvU1Kp7bKLuqVQTF2qqJ7'; // CHANGE THIS to your pool's payout address
const defaultDifficulty = 4096; //Set standard difficulty as suggested by miner
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

// Job tracking to prevent verification mismatches when templates change
const jobCache = new Map(); // Map<jobId, jobSnapshot> to store exact job states sent to miners
const JOB_CACHE_MAX_SIZE = 10; // Keep last 10 jobs to handle late submissions

console.log(`Starting Slim Stratum Solo Proxy...`);

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
 * Stores a job snapshot in the cache for later verification
 * @param {string} jobId - The job identifier (typically previous block hash)
 * @param {Object} jobSnapshot - Complete job state sent to miners
 */
function cacheJobSnapshot(jobId, jobSnapshot) {
    // Clean up old entries if cache is too large
    if (jobCache.size >= JOB_CACHE_MAX_SIZE) {
        const oldestKey = jobCache.keys().next().value;
        jobCache.delete(oldestKey);
        console.log(`Removed old job from cache: ${oldestKey}`);
    }
    
    // Store the job snapshot
    jobCache.set(jobId, {
        ...jobSnapshot,
        timestamp: Date.now()
    });
    
    console.log(`Cached job snapshot: ${jobId} (transactions: ${jobSnapshot.transactions?.length || 0})`);
}


// --- Stratum Server Logic ---

/**
 * Fetches a new block template from DigiByte Core and notifies all connected, authenticated miners
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
        //No matter what we should refresh the currentJob so as transaction details come across we have them for block submission.
        currentJob = template;
        
        //See if we have a new block in the template
        if(currentHeight === template.height){
            console.log(`Updated block template: block ${template.height} - prevhash ${template.previousblockhash}`);
            
            // Check if this is an update with transactions for an existing block
            if (template.transactions && template.transactions.length > 0) {
                console.log(`Block ${template.height} now has ${template.transactions.length} transactions - notifying miners`);
                isNewBlock = true; // Notify miners of updated template with transactions
            } else {
                //Block is not new so no need to notify any miners
                isNewBlock=false;
                console.log(`Current job is the current block height with no new transactions, so not notifying any miners.`);
            }
        }
        if(isNewBlock){ //We have a new block, so notify miners to clean_jobs and start crunching on this block
            // Warn if we're sending a template without transactions (may cause verification issues)
            if (!currentJob.transactions || currentJob.transactions.length === 0) {
                console.log(`⚠️  WARNING: Notifying miners of new block ${currentJob.height} with no transactions - this job will be cached for proper verification`);
            }
            
            // Construct a simplified mining.notify for miners (Stratum V1-like)  
            // Parameters: [job_id, prevhash, coinbase1, coinbase2, merkle_branches, version, nbits, ntime, clean_jobs]
            const jobId = currentJob.previousblockhash; // Using prevhash as job_id, common in V1
            const prevHash = currentJob.previousblockhash;
            const merkleBranches = [];
            const version = toLittleEndianHex(currentJob.version, 4); // Block version, byte-swapped
            const nBits = currentJob.bits; // Target difficulty in compact format
            const nTime = toLittleEndianHex(currentJob.curtime, 4); // Current block time, byte-swapped
            const cleanJobs = true; // Clear previous jobs
            
            console.log('DEBUGGING: Coinbase parts sent to miner:', {
                coinbase1: coinbase1,
                coinbase2: coinbase2,
                extranonce1: extranonce1,
                jobId: jobId,
                height: currentJob.height
            });

            // CRITICAL: Cache the exact job state we're sending to miners
            // This prevents verification mismatches when templates change
            cacheJobSnapshot(jobId, {
                ...currentJob, // Deep copy the current job state
                coinbase1: coinbase1,
                coinbase2: coinbase2,
                extranonce1: extranonce1
            });

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
                                    ['mining.set_difficulty', 'subscription_id'], // Subscription ID for difficulty notifications
                                    ['mining.notify', 'subscription_id'] // Subscription ID for work notifications
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
                        
                        // Send difficulty notification AFTER authorization
                        // Use config difficulty for testing - make it extremely low for guaranteed acceptance
                        socket.difficulty = config.defaultDifficulty; // Store difficulty on socket for verification
                        const difficultyNotification = JSON.stringify({
                            id: null,
                            method: 'mining.set_difficulty',
                            params: [socket.difficulty]
                        }) + '\n';
                        socket.write(difficultyNotification);
                        
                        console.log(`Miner ${socket.remoteAddress} authorized and difficulty set to ${socket.difficulty}.`);
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

                        // Extract submitted share data from miner
                        const [, submittedJobId, extranonce2, ntimeHex, nonceHex, versionBits] = request.params;

                        // CRITICAL FIX: Use cached job snapshot instead of currentJob for verification
                        const jobSnapshot = jobCache.get(submittedJobId);
                        if (!jobSnapshot) {
                            console.warn(`Miner ${socket.remoteAddress} submitted share for unknown/expired job: ${submittedJobId}`);
                            const errorResponse = JSON.stringify({
                                jsonrpc: '2.0',
                                id: request.id,
                                result: null,
                                error: [21, 'Job not found', null],
                            }) + '\n';
                            socket.write(errorResponse);
                            break;
                        }

                        console.log(`Verifying share using cached job snapshot: ${submittedJobId} (transactions: ${jobSnapshot.transactions?.length || 0})`);
                        
                        //See if we should even try to submit this block, has to be equal of greater than the currentJobBits
                        let job = {
                            jobId: submittedJobId,
                            extranonce2: extranonce2,
                            ntime: ntimeHex,
                            nonce: nonceHex,
                        }
                        let verify = await verifyShares.verifyShare(jobSnapshot, job, extranonce1, socket.difficulty || 1); // Use cached job snapshot for verification
                        let meetsShareTarget = verify.meetsShareTarget;
                        let meetsNetworkTarget = verify.meetsNetworkTarget;
                        
                        console.log(`Share verification for ${socket.remoteAddress}:`, {
                            difficulty: verify.difficulty || 'N/A',
                            poolDifficulty: socket.difficulty || 1,
                            meetsShareTarget,
                            meetsNetworkTarget,
                            hash: verify.hash?.substring(0, 16) + '...' || 'N/A'
                        });
                        if(meetsNetworkTarget){ // worthy of submission to the node
                            console.log(`Miner ${socket.remoteAddress} submitted a potential block solution! Reconstructing and submitting...`);

                            // Build the complete block using the cached job snapshot (not currentJob)
                            const blockHex = blockBuilder.buildBlock(jobSnapshot, job, extranonce1, versionBits, config);

                            // Submit the block to the Digibyte Core node
                            console.log(`Submitting block to DigiByte Core: length=${blockHex.length/2} bytes`);
                            const submissionResult = await submitBlockBuilder.submitBlock(blockHex, request.id, socket, config);
                            
                            // If block was accepted, fetch new job immediately
                            if (submissionResult.success) {
                                await fetchAndNotifyNewJob();
                            }
                            break;
                        }
                        if(meetsShareTarget){ //Worthy of a share for POW
                            //Send back a message saying we accepted the share, even though it wasn't worthy of a new block
                            socket.write(JSON.stringify({ id: request.id, result: true, error: null }) + '\n');
                            console.log(`was a good POW share but not worthy of submitting as a block, so didn't bother to submit to node.`);
                            break;
                        }
                        
                        // If we reach here, the share didn't meet either target
                        console.log(`Miner ${socket.remoteAddress} submitted invalid share - doesn't meet minimum difficulty`);
                        socket.write(JSON.stringify({ 
                            id: request.id, 
                            result: false, 
                            error: [23, 'Low difficulty share', null] 
                        }) + '\n');
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
