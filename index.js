'use strict';

const keth = require('keythereum');
const path = require('path');
const os = require('os');
const fs = require('fs');
const bcup  = require('buttercup');
const { createCredentials, FileDatasource } = bcup;
const masterpw = new WeakMap();
const cluster = require('cluster');

class AccountsManager 
{
	constructor(cfdir) 
	{
                const __watcher = (cfpath) => {
                        console.log("AccMgr: No config found, watcher triggered ...");
                        let cfgw = fs.watch(path.dirname(cfpath), (e, f) => {
                                console.log(`CastIron::__watcher: got fsevent ${e} on ${f}`);
                                if ((e === 'rename' || e === 'change') && f === path.basename(cfpath) && fs.existsSync(cfpath)) {
                                        console.log("AccMgr: got config file, parsing ...");
                                        let buffer = fs.readFileSync(cfpath);
                                        this.config = JSON.parse(buffer.toString());
                                }
                        })
                }

		try {
			let buffer = fs.readFileSync(path.join(cfdir, 'config.json'));
			this.config = JSON.parse(buffer.toString());
		} catch(err) {
			console.trace(err);
			this.config = {
				datadir: path.join(os.homedir(), '.ethereum'),
				passVault: '/dev/null'
			};

			let cfpath = path.join(cfdir, 'config.json');
			__watcher(cfpath);			
		}
		this.datadir = this.config.datadir || path.join(os.homedir(), '.ethereum');

		masterpw.set(this, {passwd: null});
	}

	password = (value) => { masterpw.get(this).passwd = value };

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

	newArchive = (masspw) => 
	{
		if (fs.existsSync(this.config.passVault)) return Promise.resolve();

		let myArchive = new bcup.Archive();
		let myGroup = myArchive.createGroup("ElevenBuckets");
		let ds = new FileDatasource(this.config.passVault);

		return ds.save(myArchive, createCredentials.fromPassword(masspw));
	}

	importFromJSON = (jsonpath, password) => 
	{
		cluster.setupMaster({exec: path.join(__dirname, './import.js')});

		if (cluster.isMaster) {
			const __recovers = (resolve, reject) =>
	        	{
				const worker = cluster.fork({jsonpath, password}); // passing via env safer than IPC?
				worker.on('message', (keyObj) => { 
					if (Object.keys(keyObj).length === 0) {
						reject(false);
					} else {
						resolve({keyObj, password});
					}
				});
				worker.on('error', () => { reject(false); });
	        	}

	        	return new Promise(__recovers);
		}
	}

	create = (password) => 
	{
		cluster.setupMaster({exec: path.join(__dirname, './create.js')});

		if (cluster.isMaster) {
	    		const __creates = (resolve, reject) => {
				const worker = cluster.fork({password, datadir: this.datadir}); // passing via env safer than IPC?
				worker.on('message', (Obj) => { 
					if (Object.keys(Obj).length === 0) {
						reject(false);
					} else {
						resolve({address: Obj.address, password});
					}
				});
				worker.on('error', () => { reject(false); });
	    		};

	    		return new Promise( __creates );
		}
	}

	update = (keyObj, password) =>
	{
	    let pw = masterpw.get(this).passwd;

	    const __update = (resolve, reject) => {
		keth.exportToFile(keyObj, path.join(this.datadir, 'keystore'), (path) =>
	        {
	                if (!fs.existsSync(path)) return reject(path);
	                console.log("Import keyfile to " + path);
			fs.chmodSync(path, '600');
	                resolve({address: keyObj.address, password});
	        });
	    }
	
	    let _stage = this.newArchive(pw)
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

	           return ds.load(createCredentials.fromPassword(pw)).then( (myArchive) =>
	           {
	                  let vaults = myArchive.findGroupsByTitle("ElevenBuckets")[0];
			  let oldEntries = vaults.findEntriesByProperty('username', '0x' + results.address);
		
			  if (oldEntries.length > 0 && oldEntries[0].getProperty('password') === results.password) {
				  console.log("password entry exists, skipping ...");
				  return myArchive;
			  }
	
	                  vaults.createEntry(results.address)
	                          .setProperty("username", '0x' + results.address)
	                          .setProperty("password", results.password);
	
	                  return myArchive;
	           })
	           .then( (myArchive) =>
	           {
	    		  return ds.save(myArchive, createCredentials.fromPassword(pw)).then( () => { return '0x' + results.address; });
	           });
	     });
	}

	newAccount = (password) => 
	{
	    let pw = masterpw.get(this).passwd;

	    return this.newArchive(pw)
	    .then( () => { return this.create(password); })
	    .then( (result) => 
	    {
	    	let ds = new FileDatasource(this.config.passVault);

	    	return ds.load(createCredentials.fromPassword(pw)).then( (myArchive) => 
	    	{
	    		let vaults = myArchive.findGroupsByTitle("ElevenBuckets")[0];
	    		vaults.createEntry(result.address)
	    		        .setProperty("username", '0x' + result.address)
	    		        .setProperty("password", result.password);
	    
	    		return myArchive;
	    	})
	    	.then( (myArchive) => 
	    	{
	    		return ds.save(myArchive, createCredentials.fromPassword(pw)).then( () => { return '0x' + result.address; });
	    	})
	    })
	}
}

module.exports = AccountsManager;

