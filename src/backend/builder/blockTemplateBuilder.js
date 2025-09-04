const rpcServices = require('../controller/rpcServices');


async function getBlockTemplate(config){
        const template = await rpcServices.callRPCService(config,'getblocktemplate', [{
            "mode": "template", // We want a template to work on.
            "rules": ["segwit"], // We support segwit rules.
            //"capabilities": ["coinbasetxn", "coinbase/append","coinbaseaux"] // IMPORTANT: This tells the node to include the transactions array and coinbaseaux data.
            "capabilities": ["coinbasetxn"]
        }]);
        return template;
}
module.exports = {
    getBlockTemplate
}
