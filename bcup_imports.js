'use strict';

const keth = require('keythereum');
const path = require('path');
const os = require('os');
const bcup  = require('buttercup');
const { createCredentials, FileDatasource } = bcup;
const Wallet = require('CastIron/core/Wallet.js');
const ciapi = new Wallet(path.join('.local', 'config.json'));
const datadir = path.join(os.homedir(), '.ethereum');
const ds = new FileDatasource(ciapi.configs.passVault);

ciapi.closeIPC();

console.log(keth.constants);

// async for performance
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

const recoverALL = (keyObjs, passes) =>
{
	let accs = Object.keys(passes);
	return Promise.all( accs.map( addr => recovers(keyObjs, addr, passes[addr])) );
}

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
