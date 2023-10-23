# pathcoin-poc
PathCoin (transfer bitcoin without network interaction) - proof of concept demonstration

This code implements the idea laid out [here](https://gist.github.com/AdamISZ/b462838cbc8cc06aae0c15610502e4da).

It 'requires' running on a network (regtest or signet) that supports BIP 119. [Bitcoin-Inquisition](https://github.com/bitcoin-inquisition/bitcoin) does that, so it makes sense to compile and run that as your Core backend.

Currently just 'first actually working setup'. It's laughably insecure, unperformant and the most important part of the code (the fidelity bond logic) has only been implemented fully for 3 parties.
Still it does kind of work (you can fund, spend the musig outputs, transfer with files, reclaim bonds after timelock and penalties for illegal spends work in restricted cases for now).

Will slowly add details here.
