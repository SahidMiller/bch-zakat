const { BITBOX } = require("bitbox-sdk")
const { Contract, Sig, HashType } = require('cashscript')
const cramer = require('cramer-bch')
const yargs = require("yargs")

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
		describe: 'private key to sign the transaction, God willing', 
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
		builder: (yargs) => yargs.option('ledger', {
			describe: 'initialized ledger for initial funds to be redeemed, God willing',
			type: 'string', 
			coerce: (arg) => Buffer.from(arg, 'hex'),
		}),
		
		handler: (argv) => {
			
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

			console.log("\n\nExpected pledge pubkeyScript:\n" + bitbox.Script.encodeP2SHOutput(pledgeScriptHash).toString('hex'));
		}
	})
	.command({
		command: 'accept <pledgedAmount> <pledgerPkh>',
		describe: 'Accept pledge into a campaign',
		builder: (yargs) => {
			
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
			.option('ledger', {
				describe: 'current ledger to pass the contract',
				type: 'string', 
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
				argv.pledgerPkh 
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
				required: true, 
			})
			.option('ledger', {
				describe: 'current ledger to pass the contract',
				type: 'string', 
				coerce: (arg) => Buffer.from(arg, 'hex')
			})
			.option('ledger-hash', {
				describe: 'current ledger hash to pass the contract',
				type: 'string', 
				coerce: (arg) => Buffer.from(arg, 'hex')
			})
		},
		handler: (argv) => {

			const campaignUtxo = { txid: argv.cid, vout: argv.cout, satoshis: argv.ctotal };

			const output = { to: bitbox.Script.encodeP2PKHOutput(argv.campaignerPkh), amount: campaignUtxo.satoshis };

			const builder = new bitbox.TransactionBuilder(argv.network);

			builder.addInput(campaignUtxo.txid, campaignUtxo.vout, 0xfffffffe);
			builder.addOutput(output.to, output.amount);
			
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
				required: true, 
			})
			.option('ledger', {
				describe: 'current ledger to pass the contract',
				type: 'string', 
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
			ledger.copy(expectedCampaignLedger, 0, 0, lastRecipientStartIndex); 
			ledger.copy(lastPledgePkh, 0, lastRecipientStartIndex + 8); 

			const campaignUtxo = { txid: argv.cid, vout: argv.cout, satoshis: argv.ctotal };

			const outputs = [
				{ to: getCampaign({ ...argv, ledger: expectedCampaignLedger }).p2shOutput, amount: campaignUtxo.satoshis - lastPledgeAmount },
				{ to: bitbox.Script.encodeP2PKHOutput(lastPledgePkh), amount: lastPledgeAmount },
			];

			const builder = new bitbox.TransactionBuilder(argv.network);

			builder.addInput(campaignUtxo.txid, campaignUtxo.vout, 0xfffffffe);
			builder.addOutput(outputs[0].to, outputs[0].amount);
			builder.addOutput(outputs[1].to, outputs[1].amount);
			
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

				expectedCampaignLedger, 
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
		Buffer.from([0x14], 'hex'), 
		ledgerHash && ledgerHash.length ? ledgerHash : hashedLedger, 
		Buffer.from([0x75], 'hex'), 
		campaignScriptRaw
	]);
	
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
		Buffer.alloc(104 + scriptVarIntLen + script.byteLength, 0), 
		Buffer.alloc(8, 0), 
		Buffer.alloc(4, 0), 
		Buffer.alloc(32, 0), 
		Buffer.alloc(8, 0) 
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


function parameterizePreimage(preimage, script) {
	const scriptVarIntLen = (script.byteLength > 252 ? 3 : 1);
	
	const encodedPreimage = [
		Buffer.alloc(104 + scriptVarIntLen, 0), 
		script,
		Buffer.alloc(8, 0), 
		Buffer.alloc(4, 0), 
		Buffer.alloc(32, 0), 
		Buffer.alloc(4, 0), 
		Buffer.alloc(4, 0) 
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
