'use strict';

const keth = require('keythereum');
const path = require('path');
const os = require('os');
const fs = require('fs');
const bcup  = require('buttercup');
const { createCredentials, FileDatasource } = bcup;
const Wallet = require('CastIron/core/Wallet.js');
const ciapi = new Wallet(path.join('.local', 'config.json'));
const datadir = path.join(os.homedir(), '.ethereum');
const ds = new FileDatasource(ciapi.configs.passVault);

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
			if (!fs.existsSync(err)) return reject(err);
			console.log(err);
		        resolve({address: keyObj.address, password});
               	});
    	    })
	});
    };

    return new Promise( __creates );
};

/*
creates(datadir, 'dc384ZU@b9lab')
.then( (results) => { console.log(results); })
.catch( (err) => { console.log(err); process.exit(1); });
*/

const newAccount = (masterpw, datadir, password) => {
    return creates(datadir, password)
    .then( (result) => 
    {
    	return ds.load(createCredentials.fromPassword(masterpw)).then( (myArchive) => 
    	{
    		let vaults = myArchive.findGroupsByTitle("ElevenBuckets")[0];
    		vaults.createEntry(result.address)
    		        .setProperty("username", result.address)
    		        .setProperty("password", result.password);
    
    		return myArchive;
    	})
    	.then( (myArchive) => 
    	{
    		return ds.save(myArchive, createCredentials.fromPassword(masterpw));
    	})
    })
}

newAccount('masterpass', datadir, 'dc384ZU@b9lab')
.then( () => { console.log("Done update bcup archive!"); })
.catch( (err) => { console.log(err); process.exit(1); });
