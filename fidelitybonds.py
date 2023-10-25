# Implements pathcoin fidelity bond outputs
# using custom Script logic and CTV transaction nesting.
import struct
from typing import List, Tuple
import hashlib
from bitcointx.core.script import (OP_CHECKSIG,
        OP_NOP4, OP_CHECKLOCKTIMEVERIFY, CScript,
        OP_IF, OP_ELSE, OP_ENDIF, OP_DROP, OP_SHA256, OP_EQUALVERIFY,
        TaprootScriptTree, CScriptWitness)
from bitcointx.core import (CTxIn, CTransaction, CMutableTransaction,
                            CTxOut, COutPoint, CTxInWitness)
from bitcointx.core.key import CPubKey, CKey, XOnlyPubKey
from bitcointx.wallet import P2TRCoinAddress
from config import SPENDING_TX_FEE_SATS, pc_single, COMMON_NSEQUENCE_VALUE
from utils import getNUMSKey

BLOCKHEIGHT_WINDOW = pc_single().blockheight_window

OP_CHECKTEMPLATEVERIFY = OP_NOP4
#
# (before discussing, a notation point: CTV(tA) -> (x) is
# shorthand for, lock spending based on knowledge of t_A
# (an adaptor secret actually, but it doesn't matter here)
# and on condition that the transaction being paid out to is x.
#
# Here, consider a 5 party case as example:
# First, we need to construct the scriptPubKey for Alice to pay her
# fidelity bond into. This requires her to construct a chain
# of CTV hashes back-to-front.
# (From gist):
# (A and TLA) OR (CTV(tA) -> (B and TLB) OR (CTV(tA) AND 
# H(SB) -> (C and TLC) OR (CTV(tA) AND H(SC) -> (D and TLD) OR
# (CTV(tA) AND H(SD) -> E)))))
#
# There are two practically very important things to note:
# 1/ though this looks like a very long script, it is not:
# the `->` symbol indicates that the CTV is binding the output to
# a *spending transaction* from this output, that contains what
# follows. This means that we really have here, only one
# <condition> OR <condition>, not 5.
# 2/ unfortunately OP_BOOLOR cannot be used here, because "TLA" means
# "OP_CHECKLOCKTIMEVERIFY" usage, and CTV means "OP_CHECKTEMPLATEVERIFY"
# usage. Both of these opcodes immediately terminate script execution
# if they fail, so we cannot check both (if the first fails) in a single
# script execution. Fortunately the solution to this is well known:
# by using OP_IF/OP_ELSE/OP_ENDIF we can allow the spender to choose which
# of the two paths will succeed and avoid executing the other.
# These two points should be enough to explain the following simple function
# for creating pathcoin fidelity bond scripts:

def pathcoin_fidelity_bond_script(pubkey_A: XOnlyPubKey, blockheight: int,
                                  T: XOnlyPubKey, ctv_hash: bytes,
                                  hash_image: bytes = b"") -> Tuple[CScript, CScript]:
    # This will be satisfiable with:
    # <signature-on-A> 1
    # for party A, after blockheight blockheight,
    # or with:
    # <signature-on-T_A> 0
    # for any party knowing t_A, the secret key of T_A,
    # as long as they are spending into the transaction
    # whose image is ctv_hash
    #
    # However, if `hash_image` is not null, we add an additional
    # OP_SHA256 OP_EQUALVERIFY condition to the ELSE clause.
    if hash_image == b"":
        script = CScript([OP_IF, blockheight, OP_CHECKLOCKTIMEVERIFY, OP_DROP,
                    pubkey_A, OP_CHECKSIG, OP_ELSE, ctv_hash,
                    OP_CHECKTEMPLATEVERIFY, OP_DROP, T, OP_CHECKSIG, OP_ENDIF],
                         name="pathcoin1")
    else:
        script = CScript([OP_IF, blockheight, OP_CHECKLOCKTIMEVERIFY, OP_DROP,
                        pubkey_A, OP_CHECKSIG, OP_ELSE,
                        hash_image, OP_SHA256, OP_EQUALVERIFY, ctv_hash,
                        OP_CHECKTEMPLATEVERIFY, OP_DROP, T, OP_CHECKSIG, OP_ENDIF],
                         name="pathcoin1")
    return get_taproot_scriptpubkey_from_script(script), script

def get_taproot_scriptpubkey_from_script(script: CScript) -> CScript:
    """ A utility function to create a taproot spk/address from a single
    script, with no keypath spending.
    """
    tree = TaprootScriptTree([script])
    # set the NUMS internal pubkey;
    internal_nums_pub = XOnlyPubKey(getNUMSKey())
    tree.set_internal_pubkey(internal_nums_pub)
    return P2TRCoinAddress.from_script_tree(tree).to_scriptPubKey()

def sha256(s) -> bytes:
    return hashlib.sha256(s).digest()

def get_standard_template_hash(tx: CTransaction, nIn: int=0) -> bytes:
    # This is the new transaction hashing algorithm for BIP 119.
    # copied from https://github.com/jamesob/simple-ctv-vault/blob/7dd6c4ca25debb2140cdefb79b302c65d1b24937/main.py#L570
    # notice we are not doing *any* caching as is discussed
    # extensively in the BIP to help performance, where that matters.
    r = b""
    r += struct.pack("<i", tx.nVersion)
    r += struct.pack("<I", tx.nLockTime)
    vin = tx.vin or []
    vout = tx.vout or []
    # we will not be using scriptSig anywhere so it is elided
    #if any(inp.scriptSig for inp in vin):
    #    r += sha256(b"".join(ser_string(inp.scriptSig) for inp in vin))
    r += struct.pack("<I", len(tx.vin))
    r += sha256(b"".join(struct.pack("<I", inp.nSequence) for inp in vin))
    r += struct.pack("<I", len(tx.vout))
    r += sha256(b"".join(out.serialize() for out in vout))
    r += struct.pack("<I", nIn)
    return sha256(r)

def get_tx_for_ctv_hash(vout, locktime=0):
    # A nuance; while CTV blanks out inputs, so we can't reuse
    # the other transaction construction, which includes them,
    # on the other hand, we must use the same nSequence values in both
    # places, as CTV *does* include that.
    return CTransaction([CTxIn(nSequence=COMMON_NSEQUENCE_VALUE)], [vout],
                        nLockTime=locktime, nVersion=2)


def create_fidelity_bond_sPK(n: int, idx: int, input_amount_sats: int, 
                          spending_key_list: List[CPubKey],
                          blockheight: int,
                          T: CPubKey,
                          fb_lock_hash_list: List[bytes],
                          destination_E: CScript,
                          unwind=False) -> Tuple[CTxOut, CScript]:
    """ We can create CTransaction objects without knowing the input's outpoint
       (here impossible due to recursion), by giving them default/uninitialized
        outpoints.
        E is a special case, because no further spending path is needed,
        we can lock in a singular destination for the punishment spend,
        instead of signing on a key to another destination. """
    n_txs = n - idx
    # the script pubkey of the final payout to the final recipient;
    # since this is not part of the custom script pattern it's outside the loop.
    current_vout = CTxOut(nValue= input_amount_sats - SPENDING_TX_FEE_SATS * (n_txs - 1),
                     scriptPubKey=destination_E)
    current_script = destination_E
    current_out_sPK = destination_E
    if unwind:
        vouts = [current_vout]
        scripts = [current_script]
    for i in range(n_txs - 1):
        # the CTV hash calculation of the transaction we're paying into; notice
        # that the CTV hash should *not* specify a non-zero locktime, because the whole
        # point of the CTV clause is to allow immediate spending to the next 'airlock'.
        current_tx_for_ctv_hash = get_tx_for_ctv_hash(current_vout)
        current_ctv_hash = get_standard_template_hash(current_tx_for_ctv_hash)
        # the script pubkey for the fidelity bond, using the above CTV hash for the second
        # clause, along with the other two conditions (the T is the adaptor, which must
        # be signed for, and the lock secret's hash image:
        # Additional note: casting from CPubKey to XOnlyPubKey as is done here,
        # is not problematic for *single* key signing (whereas in aggregation you must
        # keep track of parity).
        # if that is strange, look at:
        # https://github.com/bitcoin-core/secp256k1/blob/7006f1b97fd8dbf4ef75771dd7c15185811c3f50/src/modules/schnorrsig/main_impl.h#L155-L160
        # Note: Last txout/script we create is for the fb funding address; that script does *not*
        # need the hashlock:
        if i == n_txs - 2:
            hash_image = b""
        else:
            hash_image = fb_lock_hash_list[n - i - 2]
        current_out_sPK, current_script = pathcoin_fidelity_bond_script(
            XOnlyPubKey(spending_key_list[n - i - 2]),
            blockheight - BLOCKHEIGHT_WINDOW * (n_txs - i - 2),
            XOnlyPubKey(T),
            current_ctv_hash,
            hash_image=hash_image)
        # the TxOut for that script pubkey:
        current_vout = CTxOut(nValue=input_amount_sats - SPENDING_TX_FEE_SATS * (n_txs - i - 2),
                              scriptPubKey=current_out_sPK)
        if unwind:
            vouts.append(current_vout)
            scripts.append(current_script)
    if unwind:
        return (vouts, scripts)
    else:
        return (current_vout, current_script)

def prepare_fb_spending_tx(outpoint: COutPoint, fb_offset_value: int,
                           payout_sPK: CScript, blockheight: int, ifelse: bool=True) -> CMutableTransaction:
    # using nSequence to enable locktimes where they are used, see BIP65
    vin = [CTxIn(outpoint, nSequence=COMMON_NSEQUENCE_VALUE)] # has to be value fb_value:
    vout = [CTxOut(nValue=fb_offset_value, scriptPubKey=payout_sPK)]
    tx = CMutableTransaction(vin, vout, nVersion=2)
    # transaction must also satisfy locktime requirement:
    # however, locktime remains at 0 if we are using the CTV clause:
    if ifelse:
        tx.nLockTime = blockheight
    else:
        tx.nLockTime = 0
    return tx

def create_fidelity_bond_penalty_tx(idx_claimed_from: int, outpoint: COutPoint,
                                    payout_sPK: CScript, coin_amount: int,
                                    n: int, pcindex: int, fb_spending_keys: List[CPubKey],
                                    blockheight: int, adaptor_key: CPubKey,
                                    fb_hashlocks: List[bytes], final_fb_destination: CScript,
                                    signing_key: CKey,
                                    counterparty_adaptor_secret: CKey) -> CMutableTransaction:
    """ TODO: This is a braindead fixed 3 party case. Checking if it works, then need
    to generalize to n-party.

    In the simplest case, we will create two transactions with witnesses
     fulfilling the requirement. B will claim A's fidelity bond based on having
     extracted A's secret t_A from:
     1/ observing the schnorr sig on chain, of the spending transaction.
     2/ subtracting all the *other* participants'; partial signatures for that
        signing session.
     3. Thus deducing sigma_A1 and comparing it with the adaptor sigma'_A1.
     4. This should reveal t_A which can be verified against the published T_A.

     Start by creating the outpoint of the first transaction, then we create
     the second transaction, confirm it has the right CTV hash, fulfill its witness and then
     that of the first transaction. A rough outline:
     U_FA,start -> (TX1 via T_A and CTV) -> U_FA,B -> (TX2 via B and CLTV) -> payout
    """
    fb_value = int(coin_amount * pc_single().fidelity_bond_multiplier)
    
    # reconstruct the sPKs, from the first spend out to the one that enacts
    # the penalty. Note that the lists returned are in reverse order, i.e. they
    # start at the final destination (which is a plain destination scriptPubKey, p2wpkh).
    # Note that the blockheight field passed as argument should be the "base"/starting blockheight
    # lock of the first phase, we always calculate the later ones through offset.
    # Note that the `index` argument (the 2nd) is always the index *of the participant
    # whose fidelity bond this is*, which is only "us" for a reclaim; for a penalty, it's
    # someone else. The adaptor key in these scripts is the one corresponding to *that* index.
    txouts, scripts = create_fidelity_bond_sPK(n, idx_claimed_from,
                                        fb_value,
                                        fb_spending_keys,
                                        blockheight,
                                        adaptor_key,
                                        fb_hashlocks,
                                        final_fb_destination,
                                        unwind=True)
    # The first transaction pays *from* the outpoint of the funded
    # fidelity bond (in this case, of A), *to* the script as per above "U_FA,B",
    #, here, scripts[1]
    tx1 = prepare_fb_spending_tx(outpoint, fb_value - SPENDING_TX_FEE_SATS,
                                txouts[1].scriptPubKey, blockheight, ifelse=False)
    #
    # Creating TX2:
    txout_for_tx2 = txouts[1]
    script_for_tx2 = scripts[1] # this is the script we're spending out of
    # the outpoint of TX2 is the output of TX1, which we already prepared, unsigned.
    txid1 = tx1.GetTxid()
    outpoint2 = COutPoint(txid1, 0)
    tx2 = prepare_fb_spending_tx(outpoint2, fb_value - SPENDING_TX_FEE_SATS*2,
                                 payout_sPK, blockheight - BLOCKHEIGHT_WINDOW)
    # for valid witness, need ELSE branch, and need to sign with t_A, T_A:
    witness2 = create_fidelity_bond_witness(txout=txout_for_tx2,
                                            script=script_for_tx2,
                                            signing_key=signing_key, tx=tx2, ifelse=True)
    tx2.wit.vtxinwit[0] = witness2
    witness1 = create_fidelity_bond_witness(txout=txouts[2],script=scripts[2],
                                            signing_key=counterparty_adaptor_secret,
                                            tx=tx1, ifelse=False)
    tx1.wit.vtxinwit[0] = witness1
    # check that the ctv hash of tx1 matches what was in the script:
    # sanity check that txouts[2] gives the right fidelity bond address:
    # now we have 2 signed transactions
    return [tx1, tx2]


def create_fidelity_bond_reclaim_transaction(outpoint: COutPoint, payout_sPK: CScript, coin_amount: int,
                                             n: int, pcindex: int, fb_spending_keys: List[CPubKey],
                                             blockheight: int, adaptor_key: CPubKey,
                                             fb_hashlocks: List[bytes], final_fb_destination: CScript,
                                             signing_key: CKey) -> CMutableTransaction:
    # This returns a signed spending transaction directly from the "first level" of the script,
    # the normal path in which the originator of the FB just reclaims the money after
    # the timelock.
    fb_value = int(coin_amount * pc_single().fidelity_bond_multiplier)
    tx = prepare_fb_spending_tx(outpoint, fb_value,
                                payout_sPK, blockheight)
    # reconstruct the sPK of the input:
    txout, script = create_fidelity_bond_sPK(n, pcindex,
                                        fb_value,
                                        fb_spending_keys,
                                        blockheight,
                                        adaptor_key,
                                        fb_hashlocks,
                                        final_fb_destination)
    witness = create_fidelity_bond_witness(txout, script, signing_key, tx, True)
    tx.wit.vtxinwit[0] = witness
    return tx

def create_fidelity_bond_witness(txout: CTxOut, script: CScript,
                                 signing_key: CKey,
                                 tx,
                                 ifelse: bool=True) -> CTxInWitness:
    """ This does Schnorr signing on *a* key, for a transaction input,
    in taproot style, but note that it is not for signing a standard
    p2tr type input: it's signing using an arbitrary key in the script,
    with OP_CHECKSIG(ADD). To see the significance of the `ifelse` argument,
    see the function `pathcoin_fidelity_bond_script` above.
    """
    raw_script = bytes(script)
    new_script = CScript(raw_script, name="pathcoin1")
    tree = TaprootScriptTree([new_script])
    # TODO: tidy up this repeat
    internal_nums_pub = XOnlyPubKey(getNUMSKey())
    tree.set_internal_pubkey(internal_nums_pub)
    s, cb = tree.get_script_with_control_block('pathcoin1')
    sh = s.sighash_schnorr(tx, 0, (txout,))
    sig = signing_key.sign_schnorr_no_tweak(sh)
    # need to respect MINIMALIF in taproot:
    ifelsebyte = b"\x01" if ifelse else b""
    return CTxInWitness(CScriptWitness([sig, ifelsebyte, s, cb])) 
