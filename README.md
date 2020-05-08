# bch-zakat

Non-custodial and decentralized crowdfunding proof of concept using BCH Contracts and Covenants.

Example usage (with required global flags):

```
node bch-zakat.js <command> --network <mainnet|testnet> --campaignerPkh <string> --goal-amount <number> --goal-block <number>
```

Commands:

`launch-campaign`
`pledge --wif`
`accept <pledgedAmount> <pledgerPkh> --pledgeTxId --pledgeTxVout --campaignTxId --campaignTxVout --campaignCurrentTotal --ledger`
`claim --campaignTxId --campaignTxVout --campaignCurrentTotal --ledger`
`reclaim  --campaignTxId --campaignTxVout --campaignCurrentTotal --ledger`