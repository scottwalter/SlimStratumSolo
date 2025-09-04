const http = require('http');

// --- Digibyte Core RPC Client ---
/**
 * Makes an RPC call to the Digibyte Core server.
 * @param {string} method The RPC method to call (e.g., 'getblocktemplate', 'submitblock').
 * @param {Array} params An array of parameters for the RPC method.
 * @returns {Promise<any>} A promise that resolves with the RPC result or rejects with an error.
 */
async function callRPCService(config, method, params = []) {
    return new Promise((resolve, reject) => {
        const postData = JSON.stringify({
            jsonrpc: '2.0',
            id: 'SlimStratumSolo',
            method: method,
            params: params,
        });

        console.log(`Sending RPC payload for method '${method}':`, postData);

        const auth = 'Basic ' + Buffer.from(config.rpcAuth).toString('base64');

        const options = {
            hostname: config.rpcHost,
            port: config.rpcPort,
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
module.exports =
{
    callRPCService
}