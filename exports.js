'use strict';

const keth = require('keythereum');
const path = require('path');
const os = require('os');
const Wallet = require('CastIron/core/Wallet.js');
const ciapi = new Wallet(path.join('.local', 'config.json'));
const datadir = path.join(os.homedir(), '.ethereum');

ciapi.closeIPC();

console.log(keth.constants);

const creates = (datadir, password) => {
    const __creates = (resolve, reject) => {
	keth.create(null, function (dk) {
    	    keth.dump(password, dk.privateKey, dk.salt, dk.iv, {kdf: 'scrypt'}, function(keyObj) 
    	    {
		if (keyObj.error) return reject("Key creation failed: " + keyObj.error);

		keth.exportToFile(keyObj, path.join(datadir, 'keystore'), (err) => 
               	{
			if (err) return reject(err);
		        resolve(true);
               	});
    	    })
	});
    };

    return new Promise( __creates );
};

creates(datadir, 'dc384ZU@b9lab')
.then( (results) => { console.log(results); })
.catch( (err) => { console.log(err); process.exit(1); });
