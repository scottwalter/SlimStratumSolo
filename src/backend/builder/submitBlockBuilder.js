// submitblock_builder.js
const crypto = require('crypto');
const rpcServices = require('../controller/rpcServices');


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

module.exports = { submitBlock };
