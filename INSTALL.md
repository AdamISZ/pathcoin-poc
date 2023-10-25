## Installation

The following process works on a fresh Ubuntu 20.04 VM:

1. Optional: tor: to do the workflow on multiple remote machines, this is the most logical (setting up tor onion services for each participant and connecting that way). Do `sudo apt install tor`. Note you do *not* have to start Tor as a service; the pathcoin application starts its own Tor instance. If `which tor` returns a result, this has worked.

2. Optional: Clone the repo and then compile/build [Bitcoin-Inquisition](https://github.com/bitcoin-inquisition/bitcoin) - follow the exact same workflow as usual for *compiling* Bitcoin Core (there is no binary distribution). This process is explained in https://github.com/bitcoin-inquisition/bitcoin/blob/25.x/doc/build-unix.md. Basically, install dependencies, then `./autogen.sh`, `./configure --with-incompatible-bdb --without-gui`, `make`, `make install`. Note, if you're new to compiling Core, this can take a *long* time (you can at least try to parallelize as explained there).

3. Required: Clone the repo and then build [libsecp256k1](https://github.com/bitcoin-core/secp256k1). The build workflow (miss out `make check` unless you really want to test it) is much the same as the previous step, but it's much faster. When you do `configure`, make sure to include `./configure --enable-schnorrsig`. When done, check that `libsecp256k1.so` is present in `/usr/local/lib`, as the next step assumes this.

4. Clone *this* repository and go into its root directory. Check you have python3 on the system. Try `python3 -m venv pcvenv`. If you get an error it will tell you how to install the venv module for your Python, so do that and repeat the previous command. Then go into that virtualenv with `source pcvenv/bin/activate`. Then install the python package requirements: `pip install -r requirements.txt`. You can ignore the red warnings about `python-bitcointx`; that's just because we're not installing a full release, it will still work.

5. Now we start configuring: copy `bitcoin.conf.sample` into `~/.bitcoin/bitcoin.conf`. With that config, you can start up bitcoin already: do `bitcoind -regtest -daemon`.

6. Optional: if using tor, you need to bootstrap to get the onion address. Do `python runme.py --bootstrap 1`, or, replace '1' with your index in the list of participants (starting from 0). After a little while you'll see the onion address, save that. Get the same info from the other participants. You will put this list into the config in a moment.

7. Create pathcoin config: do a command like `python runme.py setup 1 3 100000` which is valid (TODO that's janky), then you will see that a new config file was created in `~/.pathcoin/pathcoin.cfg`. The blockchain settings should be automatically correct because of copying the bitcoin.conf as per above, but in `NETWORK`, enter `onions=<list of .onion addresses from step 6>`, if you are using Tor. If you are *not* using Tor, then enter `onions=list of localhost ports`, enter whatever ports you like.

From here you are ready to start running using the `runme.py` script, see `runme.py --help` for more info.