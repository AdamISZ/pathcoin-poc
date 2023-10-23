# pathcoin-poc
PathCoin (transfer bitcoin without network interaction) - proof of concept demonstration

This code implements the idea laid out [here](https://gist.github.com/AdamISZ/b462838cbc8cc06aae0c15610502e4da).

It 'requires' running on a network (regtest or signet) that supports BIP 119. [Bitcoin-Inquisition](https://github.com/bitcoin-inquisition/bitcoin) does that, so it makes sense to compile and run that as your Core backend.

Currently just 'first actually working setup'. It's laughably insecure, unperformant and the most important part of the code (the fidelity bond logic) has only been implemented fully for 3 parties.
Still it does kind of work (you can fund, spend the musig outputs, transfer with files, reclaim bonds after timelock and penalties for illegal spends work in restricted cases for now).


Will slowly add more details here:

### Dependencies/install:

Zero-th thing to do is to download and compile [Bitcoin-Inquisition](https://github.com/bitcoin-inquisition/bitcoin) as mentioned above. That procedure is exactly the same as for standard Bitcoin Core.

First thing is to check you have Python 3.7 or higher (I have to double check, but .8 and above are for sure fine).

Second, after cloning this repo into a local directory `pathcoin-poc`, go into it and then make a virtualenv:

```
python -m venv pcvenv
```

Next, activate it: `source pcvenv/bin/activate`.

Then, install the requirements: `pip install -r requirements.txt`. Mostly this is the twisted network dependency, and the [python-bitcointx](https://github.com/Simplexum/python-bitcointx] dependency for the Bitcoin script and transaction coding. For those unfamiliary, this was a fork of python-bitcoinlib from years ago which was much more actively developed, though it shares a similar syntax. As you notice in `requirements.txt` we need to take the latest commit, not the last release, because we need the full taproot functionality, of course.

Having done all that you're ready to run. The various functions are activated using arguments to `runme.py`.
