# pathcoin-poc
PathCoin (transfer bitcoin off-chain without network interaction) - proof of concept demonstration

This code implements the idea laid out [here](https://gist.github.com/AdamISZ/b462838cbc8cc06aae0c15610502e4da).

It requires Bitcoin Core running in signet or regtest mode. For local testing you should use [Bitcoin-Inquisition](https://github.com/bitcoin-inquisition/bitcoin), because that supports BIP 119 (for signet, it's preferable but not necessary).

### How would you use this? (i.e. test it)

The series of steps is:

* 3+ bots (or people running bots) run the `setup` and then `presign` methods (which could be folded into one, but are not, yet), to generate a `pathcoinstate*` file (currently just in working directory. This file contains keys, partial signatures etc. to allow the pathcoin to operate.
* The pathcoin's taproot address can then be funded (normally, by the first participant).
* Next, participant 0 can give the coin to participant 1, by using the `send` method, or can just spend the coin somewhere else using `spend`.
* Participant 1 would receive the coin as a base64 encoded file ( `participant0.transfer`, here), using the `receive` method to check its validity, and also checking that Participant 0's fidelity bond address has been funded. Then they, as before, can either `send` or `spend`.
* Etc. for participant 2 .. n.
* If at any time participant 0 (or 1, or any number less than current) spends the pathcoin itself, the current owner can take remedial action by using the `penalty` method.
* After the timeout defined, each participant who did fund a fidelity bond utxo can spend it, using `reclaim`.

Practically one could work with a number between 3 and 20 participants. File sizes (talking 100s of bytes to kilobytes) and computation are still perfectly fine up to 100 or more participants, but in that case, broadcasting penalty transactions would start to get problematic (e.g. 100 unconfirmed transactions chained together).

#### Just-in-time Fidelity Bonds

It's already obviously very limited to have one path of payment, i.e. one recipient per hop. And one coin denomination. Notice, though, that if you have not yet received the coin, you owe nothing and don't *need* to create a fidelity bond yet. You can wait to fund a fidelity bond until only when you want to *send* it to the next participant. If you just spend it out to an external Bitcoin address, you never need to fund a fidelity bond at all. And as explained in detail in the gist, the size of the fidelity bond utxo you fund will always be only the amount of the coin (plus a small delta, here 10%).

This can really matter if, as one might imagine, 1000 pathcoins were created amongst a small group of 20 people. They wouldn't have to lock up 1000 fidelity bonds, but only create them on the fly, *if* they need to send a pathcoin to the next person.

#### Advantages

The only reason this approach is interesting is that it creates an extreme case of non-interaction in off-chain payment. Two examples, neither of which are very practical, but at least have some sense:

1. 20 people living together in a remote village with constrained access, could, as long as they could get together *occasionally* to share network access via the "village wifi", and at the same time check the blockchain, could theoretically effect real economic payments over a long period, using such coins and transferring them as small files. It would be pretty limited due to denominations, and the collateral requirements (penalty bonds) would probably all have to be committed in advance here (effectively, locking up 100% of the value that could be transferred) to avoid needing any network/blockchain checks during usage.

2. Secret agents and similar needing super-high opsec, not wanting any ability to network trace their payments at the time they are made. A small group of people could do the initial negotiation of the pathcoinstate files in a Faraday cage, exchanging messages between their computing devices (the funding utxo could be prepared in advance of this meeting, without yet broadcasting the funding). Later one participant can fund the coin, and all the others fund penalty bonds, in separate, disconnected Bitcoin payments. Then individual transfers can be done "sitting on a park bench" with no blockchain access, no network access, only a cheap computing device capable of comparing the transfer file with the state file and ensuring cryptographic consistency. A fanciful scenario perhaps, but it has some logic.

##### A note on cost:

Payments on the path are free, i.e. literally zero sats cost, and immediate. But the collateral cost is very non-trivial, i.e. at the point of spending, you must have funded the penalty bond, which will be locked for some negotiated time. So the main cost comes in the form of sacrificed time value.

#### Caveat

This implementation of the idea is very insecure (python ECC, no testing, nowhere near enough logical checks in code, unreviewed, etc. etc.), and very unperformant.

(All this is just in case in some distant future, someone thinks they can use this code for mainnet - no, you can't.)

Still, it does function correctly - you can fund, spend the pathcoin, transfer the coin with (base64 encoded) files, reclaim bonds after timelock and penalties for illegal spends work.


### Installation:

See [INSTALL.md](./INSTALL.md). These instructions have only been tested as working on Ubuntu 20.04.

### Details on workflow

Note: in a properly developed implementation, the two first steps would be folded into *one* negotation between all the parties.

First and second steps require all parties to connect to each other (hence onions over tor or localhost with `--no-tor` option).

* `setup` - first method sets up private and public keys for musig and the fidelity bonds, then shares the public data between the participants. This initial state is persisted to file (`pathcoinstateN`). It also shows the user all the fidelity bond taproot (script path only) addresses (one per participant) and the taproot (using MuSig2) address for the pathcoin.

* `presign` - second method takes state from `setup`, as well as a funding utxo from participant 0 and negotiates nonces and then partial signatures (using MuSig1), on a different spending transaction for each participant, as per the diagrams in the PathCoin gist, so that at the end, participant 0 has all partial signatures needed for them to spend the coin into their chosen destination, but the rest do not. It persists all of this nonce and partial sig data into the file once the negotiation is complete (see note in code about care taken not to reset state, but accidentally keep the same nonce data). The pathcoin is considered active once this is complete.

Workflow now splits. From here **there is no longer a need for participants to connect to each other over a network**. If they are not physically colocated, then one-way sending of files is sufficient (or dropping them off in some server, in a 'store and forward' way, encrypted).

* Current owner can `send` (to next participant). This just means creating a file `*.transfer` which they can give to the next participant using any medium that is suitable (for example, a USB stick).

* Or, current owner can `spend` externally to their chosen destination, without requiring permission from others.

* A participant can `receive` if they are given a `*.transfer` file from the previous participant

* Any previous owner can, after the pre-agreed timeout, `reclaim` their penalty bond (if they funded it; funding the fidelity bond is done manually, outside of this application).


* A current owner can execute `penalty` on a previous owner who illegally spends the pathcoin utxo. This will broadcast a series of transactions which pays the penalty bond to the user's chosen address (the amount will be slightly higher than the original pathcoin amount).

See `./runme.py help [method]` for the syntax of any of these methods.

