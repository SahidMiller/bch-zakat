const { BITBOX } = require("bitbox-sdk")
const { Contract, Sig, HashType } = require('cashscript')
const cramer = require('cramer-bch')
const yargs = require("yargs")

//Do we need to pass just public key or private key for signing?
//Return the preimage to sign, God willing. SIGHASH_ALL | SIGHASH_ANYONECANPAY, God willing.
let bitbox = null;
yargs
	.option('campaignerPkh', {
		alias: 'c',
		describe: 'public key hash of the campaigner',
		type: 'string',
		required: true,
		coerce: (arg) => Buffer.from(arg, 'hex')
	}).option('goalAmount', {
		alias: 'a',
		describe: 'exact campaign goal in satoshis',
		type: 'number',
		required: true
	}).option('goalBlock', {
		alias: 'b',
		describe: 'exact campaign block height locked',
		type: 'number',
		required: true
	})
	.option('network', {
		alias: 'n',
		describe: 'testnet | mainnet',
		type: 'string',
		required: true
	})
	.option('broadcast', {
		alias: 'bc',
		describe: 'broadcast the result onto the network',
		type: 'boolean'
	})
	.option('new-wif', {
		alias: 'gw',
		describe: 'build a new wif',
		type: 'boolean'
	})
	.option('wif', {
		describe: 'private key to sign the transaction, God willing', //Give sighash for them to sign, then continue, God willing.
		type: 'string',
	})
	.middleware((argv) => {
		bitbox = new BITBOX({ 
			restURL: (argv.network == 'mainnet' ? 'https://rest.bitcoin.com' : 'https://trest.bitcoin.com/v2/')
		});

		if (argv.newWif) {
			const rootSeed = bitbox.Mnemonic.toSeed('test');
			const hdNode = bitbox.HDNode.fromSeed(rootSeed, argv.network);
			argv.wif = bitbox.HDNode.toKeyPair(bitbox.HDNode.derive(hdNode, 0)).toWIF();
		}

		const keypair = argv.wif && bitbox.ECPair.fromWIF(argv.wif);
		const pk = keypair && bitbox.ECPair.toPublicKey(keypair);
		const pkh = pk && bitbox.Crypto.hash160(pk);

		const campaignContract = Contract.compile(__dirname + '/cashscripts/campaign.cash', argv.network);
		const campaignInstanceRaw = campaignContract.new(argv.campaignerPkh, argv.goalAmount, argv.goalBlock);
		const campaignScriptRaw = bitbox.Script.encode(campaignInstanceRaw.redeemScript);

		const args = {
			...argv,
			keypair,
			publickey: pk,
			publickeyhash: pkh,
			campaignContract,
			pledgeContract: Contract.compile(__dirname + '/cashscripts/donator.cash', argv.network),
			campaignScriptRaw,
		};

		//Default the ledger whenever no ledger is provided but passed the required flags of the calling command (aka. it is ok with an empty ledger, God willing)
		const { script, scriptHash, p2shOutput } = getCampaign({ ...args, ledger: args.ledger || Buffer.alloc(0) });

		return {
			...args,
			currentCampaignScript: script,
			currentCampaignP2SHOutput: p2shOutput.toString('hex')
		}
	})
	.command({
		command: 'launch-campaign',
		describe: 'Launch a new campaign',

		//Option for ledger to be initialized with some state, God willing.
		builder: (yargs) => yargs.option('ledger', {
			describe: 'initialized ledger for initial funds to be redeemed, God willing',
			type: 'string', //bytes
			coerce: (arg) => Buffer.from(arg, 'hex'),
		}),

		//Broadcast or spit out the required information to broadcast, God willing.
		//Return an address with an empty amount, God willing.
		handler: (argv) => {
			//TODO GW: Can look for utxos that match, God willing, display those to use in other methods, God willing.
			console.log("\n\nInitial campaign pubkeyScript:\n" + argv.currentCampaignP2SHOutput);
		}
	})
	.command({
		command: 'pledge',
		describe: 'Returns a pledge contract to fund a campaign. \n(pledge contract requires your pkh is added to embedded ledger for you to redeem if campaign doesn\'t reach it\'s goal, God willing.)',
		handler: (argv) => {
			const campaignScriptHash = bitbox.Crypto.hash160(argv.campaignScriptRaw);
			const pledgeInstance = argv.pledgeContract.new(argv.publickeyhash, argv.campaignerPkh, campaignScriptHash);
			const pledgeScript = bitbox.Script.encode(pledgeInstance.redeemScript);
			const pledgeScriptHash = bitbox.Crypto.hash160(pledgeScript);

			//To start, just fund this contract, God willing. Any number to outputs like these, God willing.
			console.log("\n\nExpected pledge pubkeyScript:\n" + bitbox.Script.encodeP2SHOutput(pledgeScriptHash).toString('hex'));
		}
	})
	.command({
		command: 'accept <pledgedAmount> <pledgerPkh>',
		describe: 'Accept pledge into a campaign',
		builder: (yargs) => {
			//Pledge inputs
			return yargs.positional('pledgedAmount', {
				describe: 'the amount being pledged to the campaign and added to the ledger, God willing',
				type: 'number',
				required: true
			})
			.positional('pledgerPkh', {
				alias: 'ppkh',
				describe: 'the public key hash of the pledger to add to the ledger, God willing',
				type: 'string',
				required: true,
				coerce: (arg) => Buffer.from(arg, 'hex')
			})

			//Pledge inputs
			.option('pledgeTxId', {
				alias: 'pid',
				describe: 'the txid of the pledge contract to redeem',
				type: 'string',
				required: true,
				coerce: (arg) => Buffer.from(arg, 'hex')
			})
			.option('pledgeTxVout', {
				alias: 'pout',
				describe: 'the vout of the pledge contract to redeem',
				type: 'number',
				required: true
			})


			//Campaign inputs
			.option('campaignTxId', {
				alias: 'cid',
				describe: 'the campaign txid to accept pledge into',
				type: 'string',
				required: true,
				coerce: (arg) => Buffer.from(arg, 'hex')
			})
			.option('campaignTxVout', {
				alias: 'cout',
				describe: 'the vout of campaignTxId to accept pledge into',
				type: 'number',
				required: true
			})
			.option('campaignCurrentTotal', {
				alias: 'ctotal',
				describe: 'current amount in campaign script to calculate outputs manually',
				type: 'number',
				required: true
			})

			//We can use the ledger to find utxos locked specifically to this target address, God willing.
			//Otherwise, without this we want just the script itself without a ledger state, God willing.
			//Maybe another command to get the hash of a ledger + script or to pass the ledger hash here, God willing.
			//Yup, donators could use the raw contract script OR one with state. state is removed for the most part, only new state is checked, The God is most aware and uptodate on all things.
			//We need the current ledger (not hash) to make updates to it on accepting pledge, God willing. So if not provided, won't use default like launch campaign, God willing.
			.option('ledger', {
				describe: 'current ledger to pass the contract',
				type: 'string', //bytes
				coerce: (arg) => Buffer.from(arg, 'hex'),
				required: true
			})
		},
		handler: (argv) => {
			const pledgeInstance = argv.pledgeContract.new(argv.pledgerPkh, argv.campaignerPkh, bitbox.Crypto.hash160(argv.campaignScriptRaw));
			const pledgeScript = bitbox.Script.encode(pledgeInstance.redeemScript);

			const pledgedAmountBytes = UInt64LE(argv.pledgedAmount, 0);
			const updatedLedgerWithPledge = Buffer.concat([argv.ledger, pledgedAmountBytes, argv.pledgerPkh]);
			
			const pledgedUtxo = { txid: argv.pid, vout: argv.pout, satoshis: argv.pledgedAmount };
			const campaignUtxo = { txid: argv.cid, vout: argv.cout, satoshis: argv.ctotal };
			const output = { to: getCampaign({ ...argv, ledger: updatedLedgerWithPledge }).p2shOutput, amount: pledgedUtxo.satoshis + campaignUtxo.satoshis };

			const builder = new bitbox.TransactionBuilder(argv.network);
			builder.setLockTime(argv.goalBlock);

			builder.addInput(pledgedUtxo.txid, pledgedUtxo.vout, 0xfffffffe);
			builder.addInput(campaignUtxo.txid, campaignUtxo.vout, 0xfffffffe);
			builder.addOutput(output.to, output.amount);

			//Sign the sighash of the first input after building incomlete, God willing.
			const tx = builder.transaction.buildIncomplete();
			
			const pledgeSignature = signTx(tx, argv.keypair, 0, pledgeScript, pledgedUtxo.satoshis, tx.constructor.SIGHASH_ALL | tx.constructor.SIGHASH_ANYONECANPAY);
			const pledgePreimageParams = parameterizePreimageDonation(pledgeSignature.preimage, pledgeScript);

			/* pubkey publickey, sig signature, 
					bytes preimageBeforeValue, bytes8 value, bytes4 nSequence, bytes32 preimageHashOutputs, bytes8 preimageTail
					bytes campaignScript, bytes ledger, int currentCampaignTotal */
			const unlockPledgeParams = [
				argv.publickey,
				pledgeSignature.signature,
				...pledgePreimageParams,
				argv.campaignScriptRaw,
				argv.ledger, 
				bitbox.Script.encodeNumber(campaignUtxo.satoshis)
			];

			//If exists, probably needs selector as well, God willing. To choose methods, God willing.
			//If doesn't exist, don't exactly need this as an input, God willing.
			//Probably don't have to parameterize preimage twice unless transaction changed... TGIMA. God willing!
			const campaignSignature = signTx(tx, argv.keypair, 1, argv.currentCampaignScript, campaignUtxo.satoshis);
			const campaignPreimageParams = parameterizePreimage(campaignSignature.preimage, argv.currentCampaignScript);
			const acceptActionByte = Buffer.from([0], 'hex');

			/* pubkey pk, sig s, bytes1 action, ...preimage, bytes ledger, int updatedValue, bytes20 pledgerPkh */ 
			const unlockCampaignParams = [
				argv.publickey,
				campaignSignature.signature,
				acceptActionByte,
				...campaignPreimageParams, 
				argv.ledger, 
				bitbox.Script.encodeNumber(output.amount),
				argv.pledgerPkh //Very cool, so this is where both contracts agree, God willing.
			];

			builder.addInputScripts([
				{ vout: 0, script: bitbox.Script.encodeP2SHInput(unlockPledgeParams.reverse(), pledgeScript) },
				{ vout: 1, script: bitbox.Script.encodeP2SHInput(unlockCampaignParams.reverse(), argv.currentCampaignScript) }
			]);

			console.log(
				`\n\npledge pubkeyScript:\n${ bitbox.Script.encodeP2SHOutput(bitbox.Crypto.hash160(pledgeScript)).toString('hex') }\n\n` +
				`campaign pubkeyScript:\n${ argv.currentCampaignP2SHOutput }\n\n` +
				`raw transaction:\n${builder.build().toHex()}`
			);
		}
	}).command({
		command: 'claim',
		describe: 'If goal is reached, campaigner redeems full amount.',
		builder: (yargs) => {
			return yargs.option('campaignTxId', {
				alias: 'cid',
				describe: 'the campaign txid to update',
				type: 'string',
				required: true,
				coerce: (arg) => Buffer.from(arg, 'hex')
			})
			.option('campaignTxVout', {
				alias: 'cout',
				describe: 'the vout of pledgeTxId to update',
				type: 'number',
				required: true
			})
			.option('campaignCurrentTotal', {
				alias: 'ctotal',
				describe: 'current amount in campaign script to calculate outputs manually',
				type: 'number',
				required: true, //unless fetched, God willing.
			})

			//Need the hash in order to properly pass in redeem script but do not need to pass the actual ledger into contract, God willing.
			.option('ledger', {
				describe: 'current ledger to pass the contract',
				type: 'string', //bytes
				coerce: (arg) => Buffer.from(arg, 'hex')
			})
			.option('ledger-hash', {
				describe: 'current ledger hash to pass the contract',
				type: 'string', //bytes
				coerce: (arg) => Buffer.from(arg, 'hex')
			})
		},
		handler: (argv) => {

			const campaignUtxo = { txid: argv.cid, vout: argv.cout, satoshis: argv.ctotal };

			const output = { to: bitbox.Script.encodeP2PKHOutput(argv.campaignerPkh), amount: campaignUtxo.satoshis };

			const builder = new bitbox.TransactionBuilder(argv.network);

			builder.addInput(campaignUtxo.txid, campaignUtxo.vout, 0xfffffffe);
			builder.addOutput(output.to, output.amount);

			//Sign the sighash of the first input after building incomlete, God willing.
			const tx = builder.transaction.buildIncomplete();

			const { preimage, signature } = signTx(tx, argv.keypair, 0, argv.currentCampaignScript, campaignUtxo.satoshis);
			const preimageParams = parameterizePreimage(preimage, argv.currentCampaignScript);
			const acceptActionByte = Buffer.from([1], 'hex');

			/* pubkey pk, sig s, bytes1 action, ...preimage, bytes ledger, int updatedValue, bytes20 pledgerPkh */ 
			const unlockParams = [
				argv.publickey,
				signature,
				claimsActionByte,
				...preimageParams
			];

			builder.addInputScripts([
				{ vout: 0, script: bitbox.Script.encodeP2SHInput(unlockParams.reverse(), argv.currentCampaignScript) }
			]);

			console.log(`\n\ncampaign pubkeyScript:\n${ argv.currentCampaignP2SHOutput }\n\nraw transaction:\n${builder.build().toHex()}`);
		}
	}).command({
		command: 'reclaim',
		describe: 'If goal was not reached by block, pledgers can reclaim in Last-In First-Out order',
		builder: (yargs) => {
			return yargs.option('campaignTxId', {
				alias: 'cid',
				describe: 'the campaign txid to update',
				type: 'string',
				required: true,
				coerce: (arg) => Buffer.from(arg, 'hex')
			})
			.option('campaignTxVout', {
				alias: 'cout',
				describe: 'the campaign vout of campaignTxId to update',
				type: 'number',
				required: true
			})
			.option('campaignCurrentTotal', {
				alias: 'ctotal',
				describe: 'current amount in campaign script to calculate outputs manually',
				type: 'number',
				required: true, //unless fetched, God willing.
			})

			.option('ledger', {
				describe: 'current ledger to pass the contract',
				type: 'string', //bytes
				required: true,
				coerce: (arg) => Buffer.from(arg, 'hex'),
			})
		},
		handler: (argv) => {

			const ledger = argv.ledger;
			
			if (ledger.length < 28) {
				console.log("no recipients in ledger: " + ledger.toString('hex'));
				return
			}

			const lastRecipientStartIndex = ledger.length - 28;
			const expectedCampaignLedger = Buffer.alloc(lastRecipientStartIndex);
			const lastPledgeAmount = readUInt64LE(ledger, lastRecipientStartIndex);
			const lastPledgePkh = Buffer.alloc(20);
			ledger.copy(expectedCampaignLedger, 0, 0, lastRecipientStartIndex); //First 8 bytes of last 28;
			ledger.copy(lastPledgePkh, 0, lastRecipientStartIndex + 8); //Last 20bytes

			const campaignUtxo = { txid: argv.cid, vout: argv.cout, satoshis: argv.ctotal };

			const outputs = [
				{ to: getCampaign({ ...argv, ledger: expectedCampaignLedger }).p2shOutput, amount: campaignUtxo.satoshis - lastPledgeAmount },
				{ to: bitbox.Script.encodeP2PKHOutput(lastPledgePkh), amount: lastPledgeAmount },
			];

			const builder = new bitbox.TransactionBuilder(argv.network);

			builder.addInput(campaignUtxo.txid, campaignUtxo.vout, 0xfffffffe);
			builder.addOutput(outputs[0].to, outputs[0].amount);
			builder.addOutput(outputs[1].to, outputs[1].amount);

			//Sign the sighash of the first input after building incomlete, God willing.
			const tx = builder.transaction.buildIncomplete();
			builder.setLockTime(argv.goalBlock);

			const { preimage, signature } = signTx(tx, argv.keypair, 0, argv.currentCampaignScript, campaignUtxo.satoshis);
			const preimageParams = 	parameterizePreimage(preimage, argv.currentCampaignScript);

			const acceptActionByte = Buffer.from([1], 'hex');

			/* pubkey pk, sig s, bytes1 action, ...preimage, bytes ledger, int updatedValue, bytes20 pledgerPkh */ 
			const unlockParams = [
				argv.publickey,
				signature,
				claimsActionByte,
				...preimageParams,

				expectedCampaignLedger, //Without the last pledger, God willing.
				bitbox.Script.encodeNumber(outputs[0].amount),
				lastPledgePkh
			];

			builder.addInputScripts([
				{ vout: 0, script: bitbox.Script.encodeP2SHInput(unlockParams.reverse(), argv.currentCampaignScript) }
			]);

			console.log(`\n\ncampaign pubkeyScript:\n${ argv.currentCampaignP2SHOutput }\n\nraw transaction:\n${builder.build().toHex()}`);
		}
	})
	.showHelpOnFail(true)
	.help()
	.parse(process.argv.slice(2), function(err, argv, output) {

		if (err) {
			console.error(output);
			return;
		}

		console.log(output);
	});

//0x01 = SIGHASH_ALL, 0x80 = SIGHASH_ANYONECANPAY
//0 = ECDSA
function signTx(tx, keypair, input, script, amount, sighashType = 0x01 | 0x80, sigType = 0) { 
	const hashtype = sighashType | tx.constructor.SIGHASH_BITCOINCASHBIP143;
	
	const sighash = tx.hashForCashSignature(input, script, amount, hashtype);
	const signature = keypair.sign(sighash, sigType).toScriptSignature(hashtype, sigType);

	const preimageTx = cramer.Transaction.fromHex(tx.toHex());
	const preimage = preimageTx.sigHashPreimageBuf(input, script, amount, hashtype);

	return { preimage, signature };
}

function getCampaign({ campaignScriptRaw, campaignerPkh, goalAmount, goalBlock, ledger, ledgerHash }) {

	const hashedLedger = ledger && bitbox.Crypto.hash160(ledger);

	if (!hashedLedger && !ledgerHash) {
		
		throw new Error("no ledger provided for campaign");
	}

	if (hashedLedger && ledgerHash && hashedLedger !== ledgerHash) {

		console.log("mismatched hash for ledger provided. defaulting to provided hash");
	}

	const campaignScript = Buffer.concat([
		Buffer.from([0x14], 'hex'), //OP_PUSHDATA
		ledgerHash && ledgerHash.length ? ledgerHash : hashedLedger, //initialized ledger
		Buffer.from([0x75], 'hex'), //OP_DROP
		campaignScriptRaw
	]);

	//Get an address to output the new campaign, God willing.
	//That is the address to redeem pledges by, God willing.
	//To start, just fund this contract, God willing. Just want one utxo with this output, God willing.
	const campaignScriptHash = bitbox.Crypto.hash160(campaignScript);

	return {
		script: bitbox.Script.encode(campaignScript),
		scriptHash: campaignScriptHash,
		p2shOutput: bitbox.Script.encodeP2SHOutput(campaignScriptHash),
	};
}


function getPreimageSize(script) {
    const scriptSize = script.byteLength;
    const varIntSize = scriptSize > 252 ? 3 : 1;
    return 4 + 32 + 32 + 36 + varIntSize + scriptSize + 8 + 4 + 32 + 4 + 4;
}

function getInputSize(script) {
    const scriptSize = script.byteLength;
    const varIntSize = scriptSize > 252 ? 3 : 1;
    return 32 + 4 + varIntSize + scriptSize + 4;
}

// https://github.com/feross/buffer/blob/master/index.js#L1127
function verifuint (value, max) {
  if (typeof value !== 'number') throw new Error('cannot write a non-number as a number')
  if (value < 0) throw new Error('specified a negative value for writing an unsigned value')
  if (value > max) throw new Error('RangeError: value out of range')
  if (Math.floor(value) !== value) throw new Error('value has a fractional component')
}

function UInt64LE (value, offset, buffer) {
  buffer = buffer || Buffer.alloc(8);
  verifuint(value, 0x001fffffffffffff)

  buffer.writeInt32LE(value & -1, offset)
  buffer.writeUInt32LE(Math.floor(value / 0x100000000), offset + 4)
  return buffer;
}

function readUInt64LE (buffer, offset) {
  var a = buffer.readUInt32LE(offset)
  var b = buffer.readUInt32LE(offset + 4)
  b *= 0x100000000

  verifuint(b + a, 0x001fffffffffffff)

  return b + a
}

function parameterizePreimageDonation(preimage, script) {
	const scriptVarIntLen = (script.byteLength > 252 ? 3 : 1);
	
	const encodedPreimage = [
		Buffer.alloc(104 + scriptVarIntLen + script.byteLength, 0), //preimageBeforeScript, God willing.
		Buffer.alloc(8, 0), //Value placeholder
		Buffer.alloc(4, 0), //nSequence placeholder
		Buffer.alloc(32, 0), //hashOutput placeholder (used, God willing)
		Buffer.alloc(8, 0) //tail placeholder
	]

	const startValueIndex = 104 + scriptVarIntLen + script.byteLength;
	const startNSequence = startValueIndex + 8;
	const startHashOutputs = startNSequence + 4;
	const startTail = startHashOutputs + 32;
	const startEnd = startTail + 8;

	preimage.copy(encodedPreimage[0], 0, 0, startValueIndex);
	preimage.copy(encodedPreimage[1], 0, startValueIndex, startNSequence);
	preimage.copy(encodedPreimage[2], 0, startNSequence, startHashOutputs);
	preimage.copy(encodedPreimage[3], 0, startHashOutputs, startTail);
	preimage.copy(encodedPreimage[4], 0, startTail, startEnd);

	return encodedPreimage;
}

//Can work this a bit better to remove things we don't need, God willing.
function parameterizePreimage(preimage, script) {
	const scriptVarIntLen = (script.byteLength > 252 ? 3 : 1);
	
	const encodedPreimage = [
		Buffer.alloc(104 + scriptVarIntLen, 0), //preimageBeforeScript, God willing.
		script,
		Buffer.alloc(8, 0), //Value placeholder
		Buffer.alloc(4, 0), //nSequence placeholder
		Buffer.alloc(32, 0), //hashOutput placeholder (used, God willing)
		Buffer.alloc(4, 0), //locktime placeholder
		Buffer.alloc(4, 0) //sighash placeholder
	]

	const startCovenantScriptIndex = 104 + scriptVarIntLen;
	const startValueIndex = startCovenantScriptIndex + script.byteLength;
	const startNSequence = startValueIndex + 8;
	const startHashOutputs = startNSequence + 4;
	const startLock = startHashOutputs + 32;
	const startSigHash = startLock + 4;
	const startEnd = startSigHash + 4;

	preimage.copy(encodedPreimage[0], 0, 0, startCovenantScriptIndex);
	preimage.copy(encodedPreimage[2], 0, startValueIndex, startNSequence);
	preimage.copy(encodedPreimage[3], 0, startNSequence, startHashOutputs);
	preimage.copy(encodedPreimage[4], 0, startHashOutputs, startLock);
	preimage.copy(encodedPreimage[5], 0, startLock, startSigHash);
	preimage.copy(encodedPreimage[6], 0, startSigHash, startEnd);

	return encodedPreimage;
}
