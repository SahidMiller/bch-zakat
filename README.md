# bch-zakat

Non-custodial and decentralized crowdfunding proof of concept using BCH Contracts and Covenants.

Example usage (with required global flags):

```
node bch-zakat.js <command> --network <mainnet|testnet> --campaignerPkh <string> --goal-amount <number> --goal-block <number>
```

Commands:

`launch-campaign` returns a p2sh output to fund a new campaign

`pledge --wif` returns a p2sh output to pledge to a campaign

`accept <pledgedAmount> <pledgerPkh> --pledgeTxId --pledgeTxVout --campaignTxId --campaignTxVout --campaignCurrentTotal --ledger` returns a raw transaction to unlock a pledge and lock into a campaign

`claim --campaignTxId --campaignTxVout --campaignCurrentTotal --ledger` returns a raw transaction to unlock a campaign after the goal is met

`reclaim  --campaignTxId --campaignTxVout --campaignCurrentTotal --ledger` returns a raw transaction to unlock a campaign after the goal has not been met. 