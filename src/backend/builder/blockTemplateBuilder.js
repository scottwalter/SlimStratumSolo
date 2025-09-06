const rpcServices = require('../controller/rpcServices');

/**
 * Retrieves a block template from DigiByte Core for mining
 * @param {Object} config - Configuration object with RPC connection details
 * @returns {Promise<Object>} Block template containing block header info, transactions, and mining parameters
 */
async function getBlockTemplate(config) {
    const template = await rpcServices.callRPCService(config, 'getblocktemplate', [{
        mode: 'template',
        rules: ['segwit'], 
        capabilities: ['coinbasetxn']
    }]);
    return template;
}

module.exports = {
    getBlockTemplate
};
