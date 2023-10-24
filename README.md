# pathcoin-poc
PathCoin (transfer bitcoin without network interaction) - proof of concept demonstration

This code implements the idea laid out [here](https://gist.github.com/AdamISZ/b462838cbc8cc06aae0c15610502e4da).

It 'requires' running on a network (regtest or signet) that supports BIP 119. [Bitcoin-Inquisition](https://github.com/bitcoin-inquisition/bitcoin) does that, so it makes sense to compile and run that as your Core backend.

Scare quotes 'requires': it'll work on vanilla bitcoind/Bitcoin Core, only that OP_CTV invocations will be treated as NOPs, so that part of the logic will simply get ignored. Since this repo is just for testing, that doesn't seem to make a lot of sense, but ymmv.

#### Caveat

This implementation of the idea is very insecure (python ECC, no testing, nowhere near enough logical checks in code, unreviewed, etc. etc.), very unperformant and the most important part of the code (the fidelity bond logic) has only been implemented fully for 3 parties.

(All this is just in case in some distant future, someone thinks they can use this code for mainnet - no, you can't.)

Still it does kind of work (you can fund, spend the musig outputs, transfer with files, reclaim bonds after timelock and penalties for illegal spends work in restricted cases for now).


Will slowly add more details here:

### Dependencies/install:

Zero-th thing to do is to download and compile [Bitcoin-Inquisition](https://github.com/bitcoin-inquisition/bitcoin) as mentioned above. That procedure is exactly the same as for standard Bitcoin Core. (As mentioned, this is *most* likely what you want but vanilla Core still "does something").

First thing is to check you have Python 3.7 or higher (I have to double check, but .8 and above are for sure fine).

Second, after cloning this repo into a local directory `pathcoin-poc`, go into it and then make a virtualenv:

```
python -m venv pcvenv
```

Next, activate it: `source pcvenv/bin/activate`.

Then, install the requirements: `pip install -r requirements.txt`. Mostly this is the [twisted](https://github.com/twisted/twisted) network dependency, and the [python-bitcointx](https://github.com/Simplexum/python-bitcointx) dependency for the Bitcoin script and transaction coding. For those unfamiliar, this was a fork of python-bitcoinlib from years ago which was much more actively developed, though it shares the same syntax. As you notice in `requirements.txt` we need to take the latest commit, not the last release, because we need the full taproot functionality.

Having done all that you're ready to run. The various functions are activated using arguments to `runme.py`.

To see how to use `runme.py`: read `./runme.py --help`, and then `./runme.py help method` for the various methods.

### Workflow

Note: in a properly developed implementation, the two first steps would be folded into *one* online negotation between all the parties.

First and second steps require all parties to connect to each other (hence onions over tor or localhost with `--no-tor` option).

* `setup` - first method sets up private and public keys for musig and the fidelity bonds, then shares the public data between the participants. This initial state is persisted to file (`pathcoinstateN`). It also shows the user all the fidelity bond taproot (script path only) addresses (one per participant) and the taproot (using MuSig2) address for the pathcoin.

* `presign` - second method takes state from `setup`, as well as a funding utxo from participant 0 and negotiates nonces and then partial signatures (using MuSig1), on a different spending transaction for each participant, as per the diagrams in the PathCoin gist, so that at the end, participant 0 has all partial signatures needed for them to spend the coin into their chosen destination, but the rest do not. It persists all of this nonce and partial sig data into the file once the negotiation is complete (see note in code about care taken not to reset state, but accidentally keep the same nonce data). The pathcoin is considered active once this is complete.

Workflow now splits. The current owner can either `send` (to next participant) or `spend` externally to their chosen destination, without requiring permission from others. After the timeout they can `reclaim` their fidelity bond (if they funded it; funding the fidelity bond is done manually, outside of this application). They can `receive` if they are given a `.transfer` file from a previous participant, and finally they can `penalty`: execute their claim on a fidelity bond, if one of the previous owners illegally spent the coin using `spend`, after they had transferred it. See `./runme.py help method` for more details on any of these.

