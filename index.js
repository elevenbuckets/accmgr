'use strict';

const keth = require('keythereum');
const path = require('path');
const os = require('os');
const fs = require('fs');
const bcup  = require('buttercup');
const { createCredentials, FileDatasource } = bcup;


class AccountsManager 
{
	constructor(cfdir) 
	{
		let buffer = fs.readFileSync(path.join(cfdir, 'config.json'));
		this.config = JSON.parse(buffer.toString());
		this.datadir = this.config.datadir || path.join(os.homedir(), '.ethereum');
	}

	recover = (address, password) => 
	{
		let keyObj;
	
		try {
			keyObj = keth.importFromFile(address, this.datadir);
			console.log("keyfile exists with same address, checking password ...");
		} catch (err) {
			return Promise.resolve(false);
		}
	
		const __recovers = (resolve, reject) => 
		{
			console.log("Processing " + address);
		        keth.recover(password, keyObj, function(pkey) { 
				if (pkey.toString() === 'Error: message authentication code mismatch') {
					resolve(false)
				} else {
					resolve(true);
				}
			});
		}
	
		return new Promise(__recovers);
	}

	newArchive = (masterpw) => 
	{
		if (fs.existsSync(this.config.passVault)) return Promise.resolve();

		let myArchive = new bcup.Archive();
		let myGroup = myArchive.createGroup("ElevenBuckets");
		let ds = new FileDatasource(this.config.passVault);

		return ds.save(myArchive, createCredentials.fromPassword(masterpw));
	}

	importFromJSON = (jsonpath, password) => 
	{
		let keybuf = fs.readFileSync(jsonpath);
		let keyObj = JSON.parse(keybuf.toString());
	
		const __recovers = (resolve, reject) =>
	        {
	                console.log("Processing " + keyObj.address + " via file " + jsonpath);
	                keth.recover(password, keyObj, function(pkey) {
	                        if (pkey.toString() === 'Error: message authentication code mismatch') {
	                                reject(false)
	                        } else {
	                                resolve({keyObj, password});
	                        }
	                });
	        }
	
	        return new Promise(__recovers);
	}

	update = (masterpw, keyObj, password) =>
	{
	    const __update = (resolve, reject) => {
		keth.exportToFile(keyObj, path.join(this.datadir, 'keystore'), (path) =>
	        {
	                if (!fs.existsSync(path)) return reject(path);
	                console.log("Import keyfile to " + path);
	                resolve({address: keyObj.address, password});
	        });
	    }
	
	    let _stage = this.newArchive(masterpw)
	    .then( () => { return this.recover(keyObj.address, password); })
	    .then( (r) => 
	    { 
		    if (!r) {
		        return new Promise(__update);
		    } else {
			console.log("Found keyfile with same password, skip import ...");
			return {address: keyObj.address, password};
		    }
	    });
		   
	    return _stage.then( (results) => 
	    {
	    	   let ds = new FileDatasource(this.config.passVault);

	           return ds.load(createCredentials.fromPassword(masterpw)).then( (myArchive) =>
	           {
	                  let vaults = myArchive.findGroupsByTitle("ElevenBuckets")[0];
			  let oldEntries = vaults.findEntriesByProperty('username', results.address);
		
			  if (oldEntries.length > 0 && oldEntries[0].getProperty('password') === results.password) {
				  console.log("password entry exists, skipping ...");
				  return myArchive;
			  }
	
	                  vaults.createEntry(results.address)
	                          .setProperty("username", results.address)
	                          .setProperty("password", results.password);
	
	                  return myArchive;
	           })
	           .then( (myArchive) =>
	           {
	                  return ds.save(myArchive, createCredentials.fromPassword(masterpw));
	           });
	     });
	}

	create = (password) => 
	{
	    const __creates = (resolve, reject) => {
		let dk = keth.create();
	    	let keyObj = keth.dump(password, dk.privateKey, dk.salt, dk.iv, {kdf: 'scrypt'});

		if (keyObj.error) return reject("Key creation failed: " + keyObj.error);
	
		let p = keth.exportToFile(keyObj, path.join(this.datadir, 'keystore'));
		console.log("Create keyfile at " + p);

		if (!fs.existsSync(p)) return reject(p);

	        resolve({address: keyObj.address, password});
	    };
	
	    return new Promise( __creates );
	}

	newAccount = (masterpw, password) => 
	{
	    return this.newArchive(masterpw)
	    .then( () => { return this.create(password); })
	    .then( (result) => 
	    {
	    	let ds = new FileDatasource(this.config.passVault);

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
}

module.exports = AccountsManager;

