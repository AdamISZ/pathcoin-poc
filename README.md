# pathcoin-poc
PathCoin (transfer bitcoin without network interaction) - proof of concept demonstration

This code implements the idea laid out [here](https://gist.github.com/AdamISZ/b462838cbc8cc06aae0c15610502e4da).

It 'requires' running on a network (regtest or signet) that supports BIP 119. [Bitcoin-Inquisition](https://github.com/bitcoin-inquisition/bitcoin) does that, so it makes sense to compile and run that as your Core backend.

Scare quotes 'requires': it'll work on vanilla bitcoind/Bitcoin Core, only that OP_CTV invocations will be treated as NOPs, so that part of the logic will simply get ignored. Since this repo is just for testing, that doesn't seem to make a lot of sense, but ymmv.

### How would you use this? (or test it)

Practically one could work with a number between 3 and 20 participants. File sizes (talking 100s of bytes to kilobytes) and computation are still perfectly fine up to 100 or more participants, but in that case, broadcasting penalty transactions would start to get problematic (e.g. 100 unconfirmed transactions chained together).

After doing the first phase (described below), the first participant needs to fund the pathcoin.

#### Just-in-time Fidelity Bonds

It's already obviously very limited to have one path of payment, i.e. one recipient per hop. And one coin denomination. Notice, though, that if you have not yet received the coin, you owe nothing and don't *need* to create a fidelity bond yet. You can wait to fund a fidelity bond until only when you want to *send* it to the next participant. If you just spend it out to someone else, you never need to fund a fidelity bond at all. And as explained in detail in the gist, the size of the fidelity bond utxo you fund will always be only the amount of the coin (plus a small delta, here 10%).

This can really matter if, as one might imagine, 1000 pathcoins were created amongst a small group of 20 people. They wouldn't have to lock up 1000 fidelity bonds, but only create them on the fly, *if* they need to send a pathcoin to the next person.

#### Advantages

The only reason this approach is interesting is that it creates an extreme case of non-interaction in payment. 20 people living together in a remote village with constrained access, could, as long as they could get together *occasionally* to share network access via the "village wifi", and at the same time check the blockchain, could theoretically effect real economic payments over a long period, using such coins and transferring them as small files.

It also has an incredibly high value if you think in terms of the kind of extreme opsec needed by secret agents and similar. In this sense it's very much like cash - there is no network trace of the transfer(bizarrely, in this case, it might make sense to use it for *very large* amounts of money).

Payments on the path are free, i.e. literally zero sats cost, and immediate.

#### Caveat

This implementation of the idea is very insecure (python ECC, no testing, nowhere near enough logical checks in code, unreviewed, etc. etc.), and very unperformant.

(All this is just in case in some distant future, someone thinks they can use this code for mainnet - no, you can't.)

Still, it does function correctly - you can fund, spend the musig outputs, transfer the coin with (base64 encoded) files, reclaim bonds after timelock and penalties for illegal spends work.


### Installation:

See [INSTALL.md](./INSTALL.md). These instructions have only been tested as working on Ubuntu 20.04.

### Workflow

Note: in a properly developed implementation, the two first steps would be folded into *one* online negotation between all the parties.

First and second steps require all parties to connect to each other (hence onions over tor or localhost with `--no-tor` option).

* `setup` - first method sets up private and public keys for musig and the fidelity bonds, then shares the public data between the participants. This initial state is persisted to file (`pathcoinstateN`). It also shows the user all the fidelity bond taproot (script path only) addresses (one per participant) and the taproot (using MuSig2) address for the pathcoin.

* `presign` - second method takes state from `setup`, as well as a funding utxo from participant 0 and negotiates nonces and then partial signatures (using MuSig1), on a different spending transaction for each participant, as per the diagrams in the PathCoin gist, so that at the end, participant 0 has all partial signatures needed for them to spend the coin into their chosen destination, but the rest do not. It persists all of this nonce and partial sig data into the file once the negotiation is complete (see note in code about care taken not to reset state, but accidentally keep the same nonce data). The pathcoin is considered active once this is complete.

Workflow now splits. The current owner can either `send` (to next participant) or `spend` externally to their chosen destination, without requiring permission from others. After the timeout they can `reclaim` their fidelity bond (if they funded it; funding the fidelity bond is done manually, outside of this application). They can `receive` if they are given a `.transfer` file from a previous participant, and finally they can `penalty`: execute their claim on a fidelity bond, if one of the previous owners illegally spent the coin using `spend`, after they had transferred it. See `./runme.py help method` for more details on any of these.

