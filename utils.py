import binascii
import os
import sys
import json
import hashlib
import struct
from typing import List
from optparse import IndentedHelpFormatter

from bitcointx.core import CTransaction, CTxIn, CTxOut
from bitcointx.wallet import CCoinAddress, CCoinAddressError
from bitcointx.core.key import CKey, CPubKey
from bip340schnorr import int_from_bytes, bytes_from_int
from bip340schnorr import n as GROUPN
# set to true so the nonces are fixed and all the bytes are repeatable
# (but not secret)
DETERMINISTIC_TEST = True
# Exit status codes
EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EXIT_ARGERROR = 2

# optparse munges description paragraphs. We sometimes
# don't want that.
class IndentedHelpFormatterWithNL(IndentedHelpFormatter):
    def format_description(self, description):
        return description

def utxostr_to_utxo(x):
    if not isinstance(x, str):
        return (False, "not a string")
    y = x.split(":")
    if len(y) != 2:
        return (False,
                "string is not two items separated by :")
    try:
        n = int(y[1])
    except:
        return (False, "utxo index was not an integer.")
    if n < 0:
        return (False, "utxo index must not be negative.")
    if len(y[0]) != 64:
        return (False, "txid is not 64 hex characters.")
    try:
        txid = binascii.unhexlify(y[0])
    except:
        return (False, "txid is not hex.")
    return (True, (txid, n))

def utxo_to_utxostr(u):
    if not isinstance(u, tuple):
        return (False, "utxo is not a tuple.")
    if not len(u) == 2:
        return (False, "utxo should have two elements.")
    if not isinstance(u[0], bytes):
        return (False, "txid should be bytes.")
    if not isinstance(u[1], int):
        return (False, "index should be int.")
    if u[1] < 0:
        return (False, "index must be a positive integer.")
    if not len(u[0]) == 32:
        return (False, "txid must be 32 bytes.")
    txid = binascii.hexlify(u[0]).decode("ascii")
    return (True, txid + ":" + str(u[1]))

from chromalog.colorizer import GenericColorizer
from colorama import Fore, Back, Style

# magic; importing e.g. 'info' actually instantiates
# that as a function that uses the color map
# defined below. ( noqa because flake doesn't understand)
from chromalog.mark.helpers.simple import (  # noqa: F401
    debug,
    info,
    important,
    success,
    warning,
    error,
    critical,
)

pc_color_map = {
    'debug': (Style.DIM + Fore.LIGHTBLUE_EX, Style.RESET_ALL),
    'info': (Style.BRIGHT + Fore.BLUE, Style.RESET_ALL),
    'important': (Style.BRIGHT, Style.RESET_ALL),
    'success': (Fore.GREEN, Style.RESET_ALL),
    'warning': (Fore.YELLOW, Style.RESET_ALL),
    'error': (Fore.RED, Style.RESET_ALL),
    'critical': (Back.RED, Style.RESET_ALL),
}
class PCColorizer(GenericColorizer):
    default_color_map = pc_color_map

pc_colorizer = PCColorizer()

def pcprint(msg, level="info"):
    """ Provides the ability to print messages
    with consistent formatting, outside the logging system
    (in case you don't want the standard log format).
    Example applications are: REPL style stuff, and/or
    some very important / user workflow affecting communication.
    Note that this exclusively for console printout, NOT for
    logging to file (chromalog will handle file streams
    properly, but this will not).
    """
    if not level in pc_color_map.keys():
        raise Exception("Unsupported formatting")

    if sys.stdout.isatty():
        # .colorize_message function does a .format() on the string,
        # which does not work with string-ified json; this should
        # result in output as intended:
        msg = msg.replace('{', '{{')
        msg = msg.replace('}', '}}')

    fmtfn = eval(level)
    fmtd_msg = fmtfn(msg)
    if sys.stdout.isatty():
        print(pc_colorizer.colorize_message(fmtd_msg))
    else:
        print(fmtd_msg)

# hex/binary conversion routines used by dependent packages
def hextobin(h):
    """Convert a hex string to bytes"""
    return binascii.unhexlify(h.encode('utf8'))


def bintohex(b):
    """Convert bytes to a hex string"""
    return binascii.hexlify(b).decode('utf8')

def get_random_bytes_32(n, start_offset=None, extra_offset=None):
    if DETERMINISTIC_TEST:
        if start_offset is None or extra_offset is None:
            raise Exception("Deterministic random bytes call requires start and extra offset arguments.")
        return [bytes([start_offset+extra_offset+q]*32) for q in range(n)]
    else:
        # note that `[os.urandom(32)] * n` would be an oopsie!
        return [os.urandom(32) for _ in range(n)]

def getNUMSKey() -> CPubKey:
    """ Deterministic (i.e) reproducible production of a NUMS public key.
    """
    for counter in range(256):
        hashed_seed = hashlib.sha256(struct.pack(b'B', counter)).digest()
        #Every x-coord on the curve has two y-values, encoded
        #in compressed form with 02/03 parity byte. We just
        #choose the former.
        claimed_point = b"\x02" + hashed_seed
        try:
            nums_point = CPubKey(claimed_point)
            # CPubKey does not throw ValueError or otherwise
            # on invalid initialization data; it must be inspected:
            assert nums_point.is_fullyvalid()
            return nums_point
        except:
            continue
    print("Oh dear.")

def get_secret_from_spend(txhex: str, secret_offset: bytes,
                          adaptor_key: CPubKey,
                          other_partial_signatures: List[bytes],
                          inidx: int=0) -> bytes:
    """ Given a transaction `tx` that spends using a signature for which we
    were already provided an adaptor, we return the corresponding adaptor
    secret by subtraction. The spending index is provided as the third
    argument, but it would be fairly trivial to avoid that requirement.
    """
    tx = CTransaction.deserialize(hextobin(txhex))
    witness = tx.wit.vtxinwit[0].scriptWitness # assumes only one input here TODO
    print("Got witness script: ", witness)
    sig = bytes(witness.stack[0])[32:] # s only, not R
    print("Got sig: ", sig)
    # We must subtract all the other participants' partial signatures,
    # for this signing session, to get this specific participant's partial
    # signature:
    partial_sig_for_them_int = int_from_bytes(sig)
    for ps in other_partial_signatures:
        partial_sig_for_them_int -= int_from_bytes(ps) # no need to modulo until the end
    partial_sig_for_them = bytes_from_int(partial_sig_for_them_int % GROUPN)
    print("Got partial sig for them: ", bintohex(partial_sig_for_them))
    purported_adaptor_secret_int = (partial_sig_for_them_int - int_from_bytes(
        secret_offset)) % GROUPN
    purported_adaptor_secret = bytes_from_int(purported_adaptor_secret_int)
    # is it right?
    purported_adaptor = CKey.from_secret_bytes(purported_adaptor_secret).pub
    assert isinstance(purported_adaptor, CPubKey)
    if not adaptor_key == purported_adaptor:
        print("Mismatch between derived secret, producing key: {}, and expected adaptor: {}".format(
            purported_adaptor, adaptor_key))
    return purported_adaptor_secret
    
def human_readable_transaction(tx, jsonified=True):
    """ Given a CTransaction object, output a human
    readable json-formatted string (suitable for terminal
    output or large GUI textbox display) containing
    all details of that transaction.
    If `jsonified` is False, the dict is returned, instead
    of the json string.
    """
    assert isinstance(tx, CTransaction)
    outdict = {}
    outdict["hex"] = bintohex(tx.serialize())
    outdict["inputs"]=[]
    outdict["outputs"]=[]
    outdict["txid"]= bintohex(tx.GetTxid()[::-1])
    outdict["nLockTime"] = tx.nLockTime
    outdict["nVersion"] = tx.nVersion
    for i, inp in enumerate(tx.vin):
        if not tx.wit.vtxinwit:
            # witness section is not initialized/empty
            witarg = None
        else:
            witarg = tx.wit.vtxinwit[i]
        outdict["inputs"].append(human_readable_input(inp, witarg))
    for i, out in enumerate(tx.vout):
        outdict["outputs"].append(human_readable_output(out))
    if not jsonified:
        return outdict
    return json.dumps(outdict, indent=4)

def human_readable_input(txinput, txinput_witness):
    """ Pass objects of type CTxIn and CTxInWitness (or None)
    and a dict of human-readable entries for this input
    is returned.
    """
    assert isinstance(txinput, CTxIn)
    outdict = {}
    success, u = utxo_to_utxostr((txinput.prevout.hash[::-1],
                                  txinput.prevout.n))
    assert success
    outdict["outpoint"] = u
    outdict["scriptSig"] = bintohex(txinput.scriptSig)
    outdict["nSequence"] = txinput.nSequence

    if txinput_witness:
        outdict["witness"] = bintohex(
            txinput_witness.scriptWitness.serialize())
    return outdict

def human_readable_output(txoutput):
    """ Returns a dict of human-readable entries
    for this output.
    """
    assert isinstance(txoutput, CTxOut)
    outdict = {}
    outdict["value_sats"] = txoutput.nValue
    outdict["scriptPubKey"] = bintohex(txoutput.scriptPubKey)
    try:
        addr = CCoinAddress.from_scriptPubKey(txoutput.scriptPubKey)
        outdict["address"] = str(addr)
    except CCoinAddressError:
        pass # non standard script
    return outdict