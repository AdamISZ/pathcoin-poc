from optparse import OptionParser
from utils import IndentedHelpFormatterWithNL

help_strings = {}
help_strings["setup"] = """
Setup the pathcoin addresses, private keys and fidelity
bonds. arguments: my-index, number-of-participants,
coin-amount-in-sats, destination-address, blockheight.
Must be run concurrently with all other participants.

Example usage:
python runme.py 1 3 250000 bcrt1q... 466
"""
help_strings["presign"] = """
Negotiates actual partial signatures. When it is complete,
the pathcoin is in its initial valid state, and can be spent
by the first participant, only. The first participant can also
transfer it to the second.
Must be run concurrently with all other participants.
Arguments: my-index, number-of-participants,
coin-amount-in-sats, funding-utxo-str.
The last argument is only used by the first participant (the funder).

Example usage:
python runme.py 2 5 275000
or
python runme.py 0 5 275000 "72c2f842ff7c5c62eba2e3072ca87d33b6f17374f02166f5c70497ca7b4c5e1c:0"
"""

help_strings["send"] = """
Creates a pathcoin*.transfer file, that aggregates data
from previous transfers and adds signature and secret data
to it, such that the next participant can take ownership of the coin.
The data in the file is encoded in base64. Give this file to
the next participant to transfer the coin to them.
Arguments: my-index, number-of-participants,
coin-amount-in-sats.

Example usage:
python runme.py send 1 4 300000
"""

help_strings["receive"] = """
Reads a pathcoin*.transfer file transferred to us
by the previous participant, validates the signature and
secret data inside it. If validation checks pass, *and* you
have checked, in the past,
that the corresponding fidelity bonds of *all* participants
before you in the path have been funded with the right amount,
then you have ownership of the coin, without taking any action,
and can spend it at any time.
Arguments: my-index, number-of-participants, coin-amount-in-sats,
filename-of-transfer-file.

Example usage:
python runme.py receive 2 3 350000 pathcoinstate1.transfer

(notice that participant 2 is receiving a file from participant 1)
"""

help_strings["spend"] = """
Spend the pathcoin to an external destination.
If you are the current owner (have received *.transfer,
but have not sent it, or are the original owner), you can spend
to the fixed destination pre-agreed, immediately (and then spend
the unconfirmed output to a new recipient). Note this will be a
MuSig key spend, so will be a single standard Schnorr signature on chain.
Arguments: my-index, number-of-participants, coin-amount-in-sats.

Example usage:
./runme.py spend 2 5 400000
"""

help_strings["reclaim"] = """
Reclaims funds put into a fidelity bond, after the timeout.
Arguments: my-index, number-of-participants, coin-amount-in-sats,
utxo-string-of-fidelity-bond, payout-address.

Example usage:

python runme.py reclaim 0 4 375000 "72c2f842ff7c5c62eba2e3072ca87d33b6f17374f02166f5c70497ca7b4c5e1c:0" bcrt1q..
"""

help_strings["penalty"] = """
Claims another participant's fidelity bond after they illegally
spend the pathcoin.
Arguments: my-index, number-of-participants, coin-amount-in-sats,
index-of-participant-claiming-from, utxo-string-of-fidelity-bond,
our-payout-address, full-transaction-hex-of-illegal-spend

Example usage:
./runme.py penalty 1 3 100000 0 "e2....8d:0" bcrt1q... "02000000000101..."

"""

# help strings for each method:
methods = ["setup", "presign", "send", "receive", "spend", "reclaim", "penalty", "help"]


description ="""Create and spend pathcoins.
The method is one of the following:
(setup, presign, send, receive, spend, reclaim, penalty).
For explanation of each of those methods, run:
./runme.py help [method]
To run without tor use --no-tor, using localhost connections only.
To run with tor, first time, do ./runme.py --bootstrap <myindex>
and record the newly created *.onion address, add the full list
of onion addresses in the NETWORK section of your pathcoin.cfg file.
"""

def get_help(method):
    print(help_strings[method])

def get_runme_parser():
    parser = OptionParser(
            usage='usage: %prog [options] [method] [args..]',
            description=description, formatter=IndentedHelpFormatterWithNL())
    parser.add_option('--bootstrap',
        action='store_true',
        dest='bootstrap',
        default=False,
        help=('If set to true, program just prints out .onion address'
               'to share with counterparties'))
    parser.add_option('--no-tor',
                      action='store_true',
                      dest='testing',
                      default=False,
                      help=('If set to true, use localhost network'
                            ' settings, set the destination as a port'
                            ' which is implied to be on localhost.'))
    
    return parser.parse_args()