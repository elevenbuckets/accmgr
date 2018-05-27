'use strict';

const keth = require('keythereum');
const path = require('path');
const os = require('os');
const fs = require('fs');
const bcup  = require('buttercup');
const { createCredentials, FileDatasource } = bcup;

const datadir = path.join(os.homedir(), '.ethereum');

let buffer = fs.readFileSync(path.join('.local', 'config.json'));

const config = JSON.parse(buffer.toString());
const ds = new FileDatasource(config.passVault);

console.log(keth.constants);

// async for performance. read-only
const recovers = (keyObjs, address, password) => 
{
	const __recovers = (resolve, reject) => 
	{

		console.log("Processing " + address);
	        keth.recover(password, keyObjs[address], function(pkey) { 
			if (pkey.toString() === 'Error: message authentication code mismatch') {
				resolve(false)
			} else {
				resolve(true);
			}
		});
	}

	return new Promise(__recovers);
}

const recover = (datadir, address, password) => 
{
	let keyObj;

	try {
		keyObj = keth.importFromFile(address, datadir);
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

const recoverALL = (keyObjs, passes) =>
{
	let accs = Object.keys(passes);
	return Promise.all( accs.map( addr => recovers(keyObjs, addr, passes[addr])) );
}

const importAccount = (masterpw, datadir, address, password) => 
{
	return recover(datadir, address, password)
	.then( (result) => 
	{
		if (result) {
			return ds.load(createCredentials.fromPassword(masterpw)).then( (myArchive) => 
			{
				let vaults = myArchive.findGroupsByTitle("ElevenBuckets")[0];
				vaults.createEntry(address)
			                .setProperty("username", address)
				        .setProperty("password", password);

			        return myArchive;
			})
			.then( (myArchive) =>
			{
				return ds.save(myArchive, createCredentials.fromPassword(masterpw));
			});
		} else {
			throw "Wrong password for address" + address;
		}
	})
}

const newArchive = (passVault, masterpw) => 
{
	let myArchive = new bcup.Archive();
	let myGroup = myArchive.createGroup("ElevenBuckets");
	let ds = new FileDatasource(passVault);
	return ds.save(myArchive, createCredentials.fromPassword(masterpw));
}

const importFromJSON = (jsonpath, password) => 
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

// update both bcup archive and keystore
const update = (masterpw, datadir, keyObj, password) =>
{
    const __update = (resolve, reject) => {
	keth.exportToFile(keyObj, path.join(datadir, 'keystore'), (err) =>
        {
                if (!fs.existsSync(err)) return reject(err);
                console.log(err);
                resolve({address: keyObj.address, password});
        });
    }

    let _stage = recover(datadir, keyObj.address, password)
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

// MAIN
let stage = Promise.resolve();
let masterpw = 'masterpass';
let filepath = process.argv[2]; console.log(filepath); 
let password = 'dc384ZU@b9lab';

if(!fs.existsSync(config.passVault)) stage = stage.then( () => newArchive(config.passVault, masterpw) );

stage
.then( () => { return importFromJSON(filepath, password); })
.then( (r) => { return update(masterpw, datadir, r.keyObj, r.password); })
.catch((error) => { console.log(error); process.exit(1)})

/*
recovers(keyObjs, accounts[0], 'dc384ZU@b9lab')
.then( (result) => { result ? console.log("password is correct") : console.log("password is wrong"); })
.catch((error) => { console.log(error); process.exit(1)})
*/

/*
recoverALL(keyObjs, passes)
.then( (results) => { console.log(results); })
.catch((error) => { console.log(error); process.exit(1)})
*/

/*
let masterpw = 'masterpass';
ds.load(createCredentials.fromPassword(masterpw)).then( (myArchive) => 
{
	let vaults = myArchive.findGroupsByTitle("ElevenBuckets")[0];
	let accounts = ciapi.allAccounts();

	let keyObjs = {};
	let passes  = {};

	accounts.map((addr) => 
	{
		keyObjs[addr] = keth.importFromFile(addr, datadir);
		passes[addr] = vaults.findEntriesByProperty('username', addr)[0].getProperty('password');
	});

	return recoverALL(keyObjs, passes);
})
.then( (results) => { console.log(results); })
.catch((error) => { console.log(error); process.exit(1)})
*/
