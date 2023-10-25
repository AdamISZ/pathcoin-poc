# pathcoin sample file
import struct
from typing import List, Union, Any, Tuple
from hashlib import sha256
from binascii import hexlify
from base64 import b64encode, b64decode
from bitcointx.core import (CMutableTransaction, CTxOut, CMutableTxIn,
                            CMutableOutPoint)
from bitcointx.core.serialize import (ByteStream_Type,
        VectorSerializer, BytesSerializer, Serializable, ser_read)
from bitcointx.core.script import SignatureHashSchnorr
from bitcointx.core.key import XOnlyPubKey, CKey
from bitcointx.wallet import (CPubKey, P2TRCoinAddress,
                              CScript, CCoinAddress,
                              P2WPKHCoinAddress)
from bip340schnorr import int_from_bytes, tagged_hash, bytes_from_int
# internal operations just needed to do point multiply without access to secp API
# for tweak_mul:
from bip340schnorr import point_mul, lift_x, p
from bip340schnorr import n as GROUPN
from fidelitybonds import create_fidelity_bond_sPK
from config import SPENDING_TX_FEE_SATS, PATHCOIN_FILENAME_PREFIX, pc_single
from utils import get_random_bytes_32, utxostr_to_utxo

class InvalidCounterpartyNonceCommitments(Exception):
    pass

class PathCoinParticipantStateError(Exception):
    pass

class PathCoinParticipantStateDeserializationError(PathCoinParticipantStateError):
    pass
 

def privkey_to_pubkey(privkey: bytes) -> CPubKey:
    key = CKey(privkey) # default compressed
    return key.pub

def tweak_multiply(mult: bytes, pub: CPubKey) -> CPubKey:
    parity_byte = pub[0] # gives an integer
    xcoord = int_from_bytes(pub[1:]) # slicing gives bytes, not int array
    basepoint = lift_x(xcoord)
    if parity_byte == 3:
        newy = p - basepoint[1]
    else:
        newy = basepoint[1]
    pt = (basepoint[0], newy)
    newpt = point_mul(pt, int_from_bytes(mult))
    bytes_repr_y = b"\x02" if newpt[1] & 1 == 0 else b"\x03"
    bytes_repr_x = bytes_from_int(newpt[0])
    return CPubKey(bytes_repr_y + bytes_repr_x)

def bip340_signing_hash(Rbytes: bytes, Pbytes: bytes,
                        sighash: bytes) -> bytes:
    """ BIP340 compatible Fiat-Shamir
    """
    return tagged_hash("BIP0340/challenge", Rbytes + Pbytes + sighash)

def get_transaction_sighash(tx: CMutableTransaction, spending_index: int,
                            spending_out: CTxOut):
    # example: cto1 = CTxOut(10000000,
    #  P2TRCoinAddress.from_xonly_pubkey(k.xonly_pub).to_scriptPubKey())
    # given the full transaction message context, we can already calculate
    # our sighash:
    return SignatureHashSchnorr(tx, spending_index, [spending_out])

def get_mult_for_i(keys: List[bytes], i: int) -> bytes:
    keysetstr = b"".join(keys)
    return sha256(keysetstr + bytes(keys[i])).digest()

def get_agg_P_i(keys: List[bytes], i: int) -> CPubKey:
    """ Sets the aggregate pubkey component for index i.
    See `get_agg_P` for important note about sign-flipping this key.
    """
    mult = get_mult_for_i(keys, i)
    # we resort to python manipulation because bitcointx lib
    # does not expose tweak_mul:
    return tweak_multiply(mult, keys[i])

def get_agg_x_i(keys: List[bytes], privkey: CKey, i: int) -> CKey:
    """ Sets the aggregate private key for signing at index i.
    """
    assert i in range(len(keys))
    mult = get_mult_for_i(keys, i)
    intmult = int_from_bytes(mult)
    priv_int = int_from_bytes(privkey.secret_bytes)
    return CKey(bytes_from_int(priv_int * intmult % GROUPN))

def get_agg_P(keys: List[bytes]) -> CPubKey:
    agged_keys = []
    for i in range(len(keys)):
        agged_keys.append(get_agg_P_i(keys, i))
    return CPubKey.combine(*agged_keys)

def its_not_ok_to_be_odd_in_bip340(point: CPubKey,
                    scalars: List[bytes]) -> Tuple[bytes, bool]:
    """ Pass a point in compressed form (CPubKey object),
    (note, not XOnlyPubKey), and pass a list of corresponding
    scalars (private keys as bytes) - flip the sign of
    the latters, if the former has odd y coord.
    The updated scalars are returned and should be used to reset.
    """
    sign_flipped = False
    newscalars = []
    if bytes(point)[0] == 3:
        for scalar in scalars:
            xi = int_from_bytes(scalar)
            xie = GROUPN - xi
            newscalars.append(bytes_from_int(xie))
        sign_flipped = True
    else:
        newscalars = scalars
    return newscalars, sign_flipped

def flip_pubkey_sign(point: CPubKey) -> CPubKey:
    """ In case we needed to flip signs of any input keys to the algorithm,
    in order to get a valid x-only signing event, we may also need to flip
    signs of public keys that do not belong to us, in order to do verification
    of the data sent to us by counterparties.
    (NB: Flipping "sign" (in finite field treat x>n/2 as "negative"),
    # is the same as flipping y-coord parity because group order is odd)
    """
    signbyte = bytes(point)[0]
    if signbyte == 3:
        nsb = b"\x02"
    else:
        assert signbyte == 2
        nsb = b"\x03"
    # python note: indexing into bytes returns int,
    # but *slicing* into bytes returns bytes.
    return CPubKey(nsb + bytes(point)[1:])

def get_taproot_sPK(agg_P: CPubKey) -> CScript:
    addr = P2TRCoinAddress.from_xonly_output_pubkey(XOnlyPubKey(agg_P))
    sPK = addr.to_scriptPubKey()
    return sPK

class PathCoinContextContribution(Serializable):
    """ The PathCoinContextContribution is the "atom"
        of the pathcoin molecule. It represents all the public
        state belonging to one counterparty, for the pathcoin.
        The intention is that the full pathcoin context (here
        context specifically refers to public state) can be constructed
        by combining all the PathCoinContextContribution-s for all
        the counterparties. """
    def __init__(self, idx: int):
        # Purpose of initialization is to make serialization
        # with default (invalid) values possible.
        self.musig_pubkey = bytes(b"")
        self.adaptor_key = bytes(b"")
        self.destination = bytes(b"")
        # Note that the *contribution* stores the index position,
        # while the full context stores the size (n). We are not
        # checking sanity of the relation between these two values.
        self.idx = idx
        # fidelity bond key data:
        self.fidelity_bond_spending_key = bytes(b"")
        self.fidelity_bond_hash = bytes(b"")

    def stream_serialize(self, f: ByteStream_Type, **kwargs: Any) -> None:
        """ Serializes:
        musig pubkey (CPubKey == bytes)
        adaptor key (CPubKey == bytes)
        destination sPK (CScript == bytes)
        fidelity bond spending key (CPubkey == bytes)
        fidelity bond hash image (bytes)
        index in context list (4 byte little endian integer)
        """
        BytesSerializer.stream_serialize(self.musig_pubkey,
                                         f, **kwargs)
        BytesSerializer.stream_serialize(self.adaptor_key,
                                         f, **kwargs)
        BytesSerializer.stream_serialize(self.destination,
                                         f, **kwargs)
        BytesSerializer.stream_serialize(self.fidelity_bond_spending_key,
                                         f, **kwargs)
        BytesSerializer.stream_serialize(self.fidelity_bond_hash,
                                         f, **kwargs)
        f.write(struct.pack(b"<i", self.idx))

    @classmethod
    def stream_deserialize(cls, f: ByteStream_Type, **kwargs: Any) -> bytes:
        # Note that all four data types support default (invalid) empty
        # forms, therefore we can pass in these defaults from a serialization.
        musig_pubkey = CPubKey(BytesSerializer.stream_deserialize(
            f, **kwargs))
        adaptor_key = CPubKey(BytesSerializer.stream_deserialize(
            f, **kwargs))
        destination = CScript(BytesSerializer.stream_deserialize(
            f, **kwargs))
        fidelity_bond_spending_key = CPubKey(BytesSerializer.stream_deserialize(
            f, **kwargs))
        fidelity_bond_hash = BytesSerializer.stream_deserialize(
            f, **kwargs)
        idx = struct.unpack(b"<i", ser_read(f, 4))[0]
        inst = cls(idx)
        inst.musig_pubkey = musig_pubkey
        inst.adaptor_key = adaptor_key
        inst.destination = destination
        inst.fidelity_bond_spending_key = fidelity_bond_spending_key
        inst.fidelity_bond_hash = fidelity_bond_hash
        return inst

class PathCoinContext(Serializable):
    """ This class is responsible for maintaining the
    "global" state of a pathcoin, i.e. the state that is
    public and looks the same to all. The partial viewpoint
    of one of the participants is maintained in `PathCoinParticipantState`.
    """
    def __init__(self, n: int, coin_amount: int, master_timelock: int):
        # The number of participants in the MuSig
        self.n = n
        # the amount of the base pathcoin in sats
        self.coin_amount = coin_amount
        # The master timelock, as a blockheight, is the timelock
        # on the "front" transaction of each fidelity bond, i.e.
        # how long Alice has to wait to claim back her fidelity bond,
        # and therefore the last date at which the coin could still
        # theoretically be used
        self.master_timelock = master_timelock
        # These are the destination sPKs of the n possible
        # transactions paying out to each of the n counterparties,
        # and for each we will a distinct n of n musig instantiation.
        self.destination_scriptPubKeys = {}
        # the transactions we prepare spending the output into the above:
        self.spending_transactions = {}
        self.musig_pubkeys = {}
        self.adaptor_keys = {}
        self.fb_spending_keys = {}
        self.fb_hashlocks = {}
        self.agg_P = None
        # the actual sPK of the pathcoin:
        self.scriptPubKey = None
        # the funding CTxOut (stored in this form for signing)
        # (note that the default scriptpubkey is just a null string)
        self.spending_out = CTxOut(nValue=self.coin_amount)
        # the utxo reference as a COutPoint
        self.outpoint = None
        # individual contributions to the context:
        self.contribs = {}
        # keeping track of x-only shenanigans based on aggregate key:
        self.key_sign_flipped = False

    def add_destination(self, idx: int, sPK: CScript) -> None:
        self.destination_scriptPubKeys[idx] = sPK

    def add_adaptor_keys(self, idx: int, adaptor_key: CPubKey) -> None:
        self.adaptor_keys[idx] = adaptor_key

    def add_fb_spending_keys(self, idx: int, fb_spending_key: CPubKey) -> None:
        self.fb_spending_keys[idx] = fb_spending_key

    def add_fb_hashlocks(self, idx: int, fb_hashlock: bytes) -> None:
        self.fb_hashlocks[idx] = fb_hashlock

    def add_contribution(self, idx: int, contrib: PathCoinContextContribution) -> bool:
        self.contribs[idx] = contrib
        return self.try_to_finalize_keyset()

    def try_to_finalize_keyset(self) -> bool:
        if not (len(self.contribs.keys()) == self.n and set(self.contribs.keys()) == set(range(self.n))):
            return False
        for i in range(self.n):
            self.add_destination(i, self.contribs[i].destination)
            self.add_adaptor_keys(i, self.contribs[i].adaptor_key)
            # final invocation will trigger calculation of MuSig sPK:
            self.add_musig_pubkeys(i, self.contribs[i].musig_pubkey)
            self.add_fb_spending_keys(i, self.contribs[i].fidelity_bond_spending_key)
            self.add_fb_hashlocks(i, self.contribs[i].fidelity_bond_hash)
        return True

    def add_musig_pubkeys(self, idx, pubkey):
        self.musig_pubkeys[idx] = pubkey
        if len(self.musig_pubkeys.keys()) == self.n:
            self.set_scriptPubKey_from_keys()
    
    def set_funding_and_spends(self, funding_utxo: str) -> None:
        """ sets the the concrete spending event, which
        funded the scriptPubKey of the PathCoin.
        """
        success, txidout = utxostr_to_utxo(funding_utxo)
        assert success, "Invalid utxo string"
        txid, outindex = txidout
        spent_script = self.scriptPubKey
        self.spending_out = CTxOut(self.coin_amount, spent_script)
        self.outpoint = CMutableOutPoint(txid[::-1], outindex)
        # once we have the scriptPubKey and the input,
        # we can construct each of the 5 potential spending
        # transactions that are the messages we need to sign
        # for each MuSig instantiation.
        self.set_spending_transactions()

    def set_scriptPubKey_from_keys(self):
        """ If we have all the musig pubkeys provided,
        we can go ahead and call the aggregation routine.
        """
        assert len(self.musig_pubkeys.keys()) == self.n
        # must be careful to ensure that the list of keys is added
        # in a fixed order:
        self.agg_P = get_agg_P([self.musig_pubkeys[i] for i in range(self.n)])
        _, x = its_not_ok_to_be_odd_in_bip340(
            self.agg_P, [])
        # caller can use this as a signal to flip the private key information:
        self.key_sign_flipped = x        
        self.scriptPubKey = get_taproot_sPK(self.agg_P)

    def get_address(self) -> str:
        return CCoinAddress.from_scriptPubKey(self.scriptPubKey)

    def set_spending_transactions(self):
        # Note: these are *not* timelocked (that's a big part of the point
        # of the system!), so the nsequence is basically 'final', but we could
        # RBF or whatever:
        vin = [CMutableTxIn(prevout=self.outpoint, nSequence=0xffffffff)]
        receiving_val = self.spending_out.nValue - SPENDING_TX_FEE_SATS
        for i in range(self.n):
            vout = [CTxOut(receiving_val, self.destination_scriptPubKeys[i])]
            tx = CMutableTransaction(vin, vout, nVersion=2)
            self.spending_transactions[i] = tx

    def get_sighash(self, idx: int):
        return get_transaction_sighash(self.spending_transactions[idx],
                                       0, self.spending_out)

    def get_final_fb_destination(self):
        return P2WPKHCoinAddress.from_pubkey(
            self.fb_spending_keys[self.n - 1]).to_scriptPubKey()

    def stream_serialize(self, f: ByteStream_Type, **kwargs: Any) -> None:
        """ Serializes:
            master_timelock (int)
            spending out (CTxOut) (this is needed for signing)
            musig pubkeys (CPubKey == bytes)
            adaptor keys (CPubkey == bytes)
            destination sPKs (CScript == bytes)
            fidelity bond spending keys (CPubkey == bytes)
            fidelity bond hashlocks (bytes)
            funding outpoint (COutPoint)
            As explained in deserialize, the remaining context
            is derivable."""
        # "4 billion blocks ought to be enough for anyone" - Bill Gates
        f.write(struct.pack(b"<i", self.master_timelock))
        # the amout of the coin
        f.write(struct.pack(b"<i", self.coin_amount))
        # note that this may not be initialized with non-null values
        self.spending_out.stream_serialize(f, **kwargs)
        for i in range(self.n):
            BytesSerializer.stream_serialize(self.musig_pubkeys[i],
                                             f, **kwargs)
        for i in range(self.n):
            BytesSerializer.stream_serialize(self.adaptor_keys[i],
                                             f, **kwargs)
        for i in range(self.n):
            BytesSerializer.stream_serialize(self.destination_scriptPubKeys[i],
                                             f, **kwargs)
        for i in range(self.n):
            BytesSerializer.stream_serialize(self.fb_spending_keys[i],
                                             f, **kwargs)
        for i in range(self.n):
            BytesSerializer.stream_serialize(self.fb_hashlocks[i],
                                             f, **kwargs)
        self.outpoint.stream_serialize(f, **kwargs)

    @classmethod
    def stream_deserialize(cls, f: ByteStream_Type, **kwargs: Any) -> bytes:
        """ Create an instance of PathCoinContext from
        serialized data: musig pubkeys, a paid into utxo with
        an amount.
        From the musig pubkeys we recreate the pathcoin sPK.
        From the utxo data and the destination sPKs,
        we recreate the spending transactions.
        """
        master_timelock = struct.unpack(b"<i", ser_read(f, 4))[0]
        coin_amount = struct.unpack(b"<i", ser_read(f, 4))[0]
        spending_out = CTxOut.stream_deserialize(f, **kwargs)
        existing_sPK = None
        if len(spending_out.scriptPubKey) != 0:
            existing_sPK = spending_out.scriptPubKey
        v_musig_pubkeys = VectorSerializer.stream_deserialize(
            f, element_class=CPubKey, **kwargs)
        inst = cls.__init__(len(v_musig_pubkeys), coin_amount, master_timelock)
        assert isinstance(inst, PathCoinContext)
        # overwrite the spending out, *if* its script was non null:
        if existing_sPK is not None:
            inst.spending_out.scriptPubKey = existing_sPK
        v_adaptor_keys = VectorSerializer.stream_deserialize(
            f, element_class=CPubKey, **kwargs)
        for i, mp in enumerate(v_musig_pubkeys):
            inst.add_musig_pubkeys(i, mp)
        for i, ak in enumerate(v_adaptor_keys):
            inst.add_adaptor_keys(i, ak)
        v_destination_sPKs = VectorSerializer.stream_deserialize(
            f, element_class=CScript, **kwargs)
        for i, dspk in enumerate(v_destination_sPKs):
            inst.add_destination(i, dspk)
        inst.outpoint = CMutableOutPoint.stream_deserialize(f, **kwargs)
        # we only finalize the context if the funding data is non-null:
        if inst.outpoint.hash != b"\x00"*32 and inst.spending_out.nValue != -1:
            inst.set_spending_transactions()
        return inst


class PathCoinParticipantState(Serializable):
    """ encapsulates the state
    which must be maintained for one user, distinct
    from other users in the set of n.
    In particular, any data private to this user,
    such as nonces/keys, are kept here and not in the
    context, which is treated as quasi-public.
    This requires pre-creation of a PathCoinContext,
    but this is simple as in bare form it only contains the
    number of participants n.
    """
    def __init__(self, idx: int,
                 context: PathCoinContext,
                 destination: CScript,
                 privkey: Union[CKey, None]=None,
                 nonces: Union[List[CKey], None]=None,
                 adaptor: Union[CKey, None]=None,
                 fb_spending_key: Union[CKey, None]=None,
                 fb_hashlock_preimage: Union[bytes, None]=None):
        # Secret material:
        if privkey is None:
            self.signing_key = CKey.from_secret_bytes(get_random_bytes_32(1, start_offset=idx, extra_offset=1)[0])
        else:
            self.signing_key = privkey
        # we need only one adaptor, for our own signing event:
        if adaptor is None:
            self.adaptor_secret = get_random_bytes_32(1, start_offset=idx, extra_offset=100)[0]
        else:
            self.adaptor_secret = adaptor
        # secrets for fidelity bond
        if fb_spending_key is None:
            self.fb_spending_key = get_random_bytes_32(1, start_offset=idx, extra_offset=150)[0]
        else:
            self.fb_spending_key = fb_spending_key
        if fb_hashlock_preimage is None:
            self.fb_hashlock_preimage = get_random_bytes_32(1, start_offset=idx, extra_offset=200)[0]
        else:
            self.fb_hashlock_preimage = fb_hashlock_preimage
        # initialize our contribution context:
        self.contrib_context = PathCoinContextContribution(idx)
        self.contrib_context.musig_pubkey = privkey_to_pubkey(
            self.signing_key)
        self.contrib_context.adaptor_key = privkey_to_pubkey(
            self.adaptor_secret)
        self.contrib_context.destination = destination
        self.contrib_context.fidelity_bond_spending_key = privkey_to_pubkey(self.fb_spending_key)
        self.contrib_context.fidelity_bond_hash = sha256(self.fb_hashlock_preimage).digest()
        self.context = context
        self.context.add_contribution(idx, self.contrib_context)
        # we need one random nonce per signing session. This can be specified
        # in the constructor, but note that deserialization might of necessity
        # *not* include nonces that were used before (in which case, "None"):
        if nonces is None:
            # if DETERMINISTIC_TEST is set, it triggers the extra vars
            self.nonces = get_random_bytes_32(self.context.n, start_offset=idx, extra_offset=50)
        else:
            self.nonces = nonces
        # need to keep track of whether we had to flip our nonce parity
        # after musig aggregation:
        self.nonce_sign_flipped = {}
        # initialize our row of the nxn matrix of nonce points:
        self.nonce_points = {idx: [privkey_to_pubkey(x) for x in self.nonces]}
        # initialize our row of the nxn matrix of nonce points and commitments:
        self.nonce_hashes = {}
        self.set_nonce_commitments(cmt=True)
        # there will be `n` aggregate R values:
        self.agg_Rs = {}
        # signal that we have finished nonce processing in this state:
        self.all_nonces_complete = False
        # the participant state will also store, persistently, the set
        # of partial signatures which are transferred to us (or, ours).
        self.partial_sigs = {}
        for i in range(self.context.n):
            self.partial_sigs[i] = [b"\x00"] * self.context.n
        self.signature_adaptors = {}
        for i in range(self.context.n):
            self.signature_adaptors[i] = b"\x00" * 32
        # stores any fidelity bond hashlock preimages that
        # are collected from transfers, to be persisted in case
        # we need to penalize:
        self.fb_hashlock_preimages = [b"\x00"] * self.context.n
        # stores any adaptor secrets for *other* participants
        # that were revealed by illegal spends:
        self.adaptor_secrets = {}

    def set_all_my_partial_signatures(self, sigs, adaptor):
        """ The arguments are the outputs from the corresponding
        function in PathCoinSigner."""
        for i in range(self.context.n):
            self.partial_sigs[i][self.contrib_context.idx] = sigs[i]
        self.signature_adaptors[self.contrib_context.idx] = adaptor

    def set_nonce_commitments(self, idx:int =None, cmt: bool=False,
                              nonce_points: List=[]) -> bool:
        """ For the participant at index idx, store the `R` nonce values,
            or the commitments to them, depending on the flag `cmt`,
            one for each of the n signing events. Return true if,
            after this event, the full set of nonces for all pathcoin
            signing sessions are available to this participant."""
        if idx is None:
            # special case for storing our own nonce/hashes upfront
            idx = self.contrib_context.idx
            if cmt:
                hashes = [sha256(self.nonce_points[idx][i]).digest() for i in range(self.context.n)]
            # There is no "else"; we already initialized our own nonce points.
        else:
            if cmt:
                hashes = nonce_points
            else:
                # if not a commitment, we need to verify the commitment opens
                # correctly
                hashes_to_verify = [sha256(x).digest() for x in nonce_points]
                if not hashes_to_verify == self.nonce_hashes[idx]:
                    print("hash check failed. hashes to verify was: ", [hexlify(x).decode() for x in hashes_to_verify],
                          " and self.nonce_hashes was: ", [hexlify(x).decode() for x in self.nonce_hashes[idx]])
                    raise InvalidCounterpartyNonceCommitments()
        if cmt:
            self.nonce_hashes[idx] = list(hashes)
            if len(self.nonce_hashes.keys()) == self.context.n:
                return True
        else:
            self.nonce_points[idx] = nonce_points
            if len(self.nonce_points.keys()) == self.context.n:
                # notice you cannot set *any* aggregate R, until
                # *all* participants have sent their lists (rows vs
                # columns in the matrix); hence we set them all at once.
                self.set_aggregate_Rs()
                return True
        return False

    def set_aggregate_Rs(self):
        for idx in range(self.context.n):
            key_list = []
            for i in range(self.context.n):
                key_list.append(self.nonce_points[i][idx]) # i: participant ; idx: signing session
            # we don't add the adaptor, commented out:
            # key_list.append(self.context.adaptor_keys[idx])
            self.agg_Rs[idx] = CPubKey.combine(*[CPubKey(np) for np in key_list])
            self.reset_base_nonce_with_aggR(idx)
            # having completed setting of nonce values, we signal that
            # nonces are ready for signature processing
            self.all_nonces_complete = True

    def reset_base_nonce_with_aggR(self, idx: int, include_t: bool=False):
        """deduces whether the base nonce sign, for this
        participant, for this signing session, needs to be flipped,
        depending on the aggregate nonce's parity.
        """
        scalarlist = [self.nonces[idx]]
        if include_t:
            scalarlist.append(self.adaptor_secret)
        newscalarlist, x = its_not_ok_to_be_odd_in_bip340(
            self.agg_Rs[idx], scalarlist)
        self.nonces[idx] = newscalarlist[0]
        if include_t:
            self.adaptor_secret = newscalarlist[1]
        self.nonce_sign_flipped[idx] = x

    def set_context_contribution(self, idx, contrib: PathCoinContextContribution) -> None:
        # Once all `n` contributions are added here, the full PathCoinContext
        # object is constructed.
        self.context.add_contribution(idx, contrib)

    def set_funding_event(self, funding_utxo: str) -> None:
        """ This is needed to allow us to construct the outpoint
        we're spending, but note, due to segwit, this funding event may not
        yet have been broadcast."""
        self.context.set_funding_and_spends(funding_utxo)
        self.save()

    def register_illegal_adaptor_usage(self, secret: bytes, idx: int) -> None:
        self.adaptor_secrets[idx] = secret

    def set_fidelity_bond_txout(self) -> None:
        self.fidelity_bond_txout = self.get_fidelity_bond_txout(self.context.master_timelock)

    def get_fidelity_bond_txout(self, blockheight: int, index=None) -> CTxOut:
        """ Given a starting blockheight (others are deltas), and an index
        for which the default "None" means "us", we can calculate the scriptpubkey
        of the fidelity bond.
        """
        idx = self.contrib_context.idx if index is None else index
        # the final receiver's fidelity bond spending key is converted
        # to a plain p2wpkh destination sPK, since they don't need to
        # create the custom fidelity bond sPK:
        final_fb_destination = self.context.get_final_fb_destination()
        fb_value = int(self.context.coin_amount * pc_single().fidelity_bond_multiplier)
        return create_fidelity_bond_sPK(self.context.n,
                                        idx,
                                        fb_value,
                                        [self.context.fb_spending_keys[i] for i in range(self.context.n)],
                                        blockheight,
                                        self.context.adaptor_keys[idx], #self.contrib_context.adaptor_key,
                                        [self.context.fb_hashlocks[i] for i in range(self.context.n)],
                                        final_fb_destination)[0]

    def human_readable(self, safe=True, funded=True) -> str:
        """ We will print out:
        1. index
        2. coin value
        2. funding outpoint (if funded)
        3. destination address
        1. signing key (not safe)
        2. adaptor secret (not safe)
        3. index
        4. nonces (not safe)
        5. (if funded) All nonce points in matrix.
        6. (if funded) All adaptor keys
        7. All partial sigs in matrix.
        8. All signature adaptors.
        TODO: correct the formatting so it's actually human readable ...
        """
        to_print = ["Full contents of the State object: "]
        to_print.append("Index: {}".format(self.contrib_context.idx))
        to_print.append("Coin value in satoshis: {}".format(self.context.spending_out.nValue))
        if funded:
            to_print.append("Funding outpoint: {}".format(self.context.outpoint))
        to_print.append("Address of coin: {}".format(self.context.get_address()))
        if not safe:
            to_print.append("Private signing key: {}".format(hexlify(self.signing_key).decode()))
            to_print.append("Adaptor secret: {}".format(hexlify(self.adaptor_secret).decode()))
        if funded:
            to_print.append("All nonce points: {}".format(self.nonce_points))
            to_print.append("All adaptor points: {}".format(self.context.adaptor_keys))
        to_print.append("All known partial signatures: {}".format(self.partial_sigs))
        to_print.append("All known adaptor signatures: {}".format(self.signature_adaptors))
        from pprint import pformat
        return pformat(to_print)

    def stream_serialize(self, f: ByteStream_Type, funding: bool=False,
                         **kwargs: Any) -> None:
        """ The serialization of this object stores:
        1. The PathCoinContributionContext objects, as a list.
        (it is assumed to be a full list).
        2. The funding outpoint
        3. The coin amount
        4. The funding spending out (CTxOut)
        5. The master locktime (int) (needed by the Context object)
        6. The signing key of this user.
        7. The index in the list of this user.
        8. The fidelity bond spending private key of this user.
        9. The fidelity bond hashlock preimage of this user.
        10a. (Optional): This user's k values.
        10b. (Optional): All R values. (must be a complete list)
        10c. (Optional): This user's t value.
        10d. (Optional): All T values.
        11. (Optional): All known partial signatures.
        12. (Optional): All known signature adaptors.
        13. (Optional): All known fidelity bond hashlock preimages.
        NOTE: It is not sound to treat the nonces and nonce points
        as items to be stored in persistent state, unless the entirety
        of nonce negotiation is complete, because:
        if we reuse the same nonce, but an adversary chooses a different
        value in re-negotiation of partial signatures, then we will create
        a new partial signature:
        s2 = k + e2 x
        after having created one before:
        s1 = k + e1 x
        where e1 =/= e2 because the adversary changed their nonce. This
        would leak our private key.
        On the other hand, if we keep *all* nonces after first round musig is
        complete, it is safe.
        Thus we need to define clearly a cut-off point: before this,
        we must restart the MuSig process from the beginning, but we must
        be able to continue with a persisted state for pathcoins which have
        been funded.
        This is defined by the kwarg "funded" to this function:
        if it is set, we will add in *all* the nonce points R, and all the
        partial signatures we currently know about, and all the adaptors
        we currently know about. If it is not, we will not store any of this,
        and if we recreate the object from disk in this latter case, we will
        have to renegotiate everything (so the assumption is that the pathcoin
        has *not* been funded, in that case).
        """
        # For simplicity, we consider that a "context" is an aggregation
        # of context contributions always, so we always serialize the full
        # list of context contributions, in order.
        VectorSerializer.stream_serialize([self.context.contribs[i] for i in range(
            self.context.n)], f)
        # Additionally, we store the funding utxo information from the full
        # context, if it is available, otherwise it is a null/default value. 
        if self.context.outpoint is None:
            outpoint_to_serialize = CMutableOutPoint()
        else:
            outpoint_to_serialize = self.context.outpoint
        outpoint_to_serialize.stream_serialize(f, **kwargs)
        f.write(struct.pack(b"<i", self.context.coin_amount))
        if len(self.context.spending_out.scriptPubKey) == 0:
            spending_out_to_serialize = CTxOut()
        else:
            spending_out_to_serialize = self.context.spending_out      
        spending_out_to_serialize.stream_serialize(f, **kwargs)
        f.write(struct.pack(b"<i", self.context.master_timelock))
        # the signing key is stored (alternatively one could store
        # a BIP32 path and run the signer as an independent module, TODO)
        # and hence ,this is the reason encryption is needed for persistence.
        BytesSerializer.stream_serialize(self.signing_key.secret_bytes, f)
        # write the 'index' (the `n` is implicit from the initial list,
        # assuming we will never store the participant state without a full
        # set of context contributions), could technically be avoided but
        # scanning for it is ugly:
        f.write(struct.pack(b"<i", self.contrib_context.idx))
        # fidelity bond private key material to allow reclaiming or pushing
        # forwards:
        BytesSerializer.stream_serialize(self.fb_spending_key, f)
        BytesSerializer.stream_serialize(self.fb_hashlock_preimage, f)
        # Now we include the optional sections, flag their existence first:
        to_write = b"\x01" if funding else b"\x00"
        f.write(to_write)
        if funding:
            # the secret k-values for this user:
            for i in range(self.context.n):
                BytesSerializer.stream_serialize(self.nonces[i],
                                                 f, **kwargs)
            # all R values (see above reasoning why it *must* be all):
            for i in range(self.context.n):
                for j in range(self.context.n):
                    BytesSerializer.stream_serialize(
                        self.nonce_points[i][j], f, **kwargs)
            # this user's secret adaptor (t-value) for his signing session:
            BytesSerializer.stream_serialize(self.adaptor_secret,
                                               f, **kwargs)
            # all adaptor points (T-values)
            for i in range(self.context.n):
                BytesSerializer.stream_serialize(
                    self.context.adaptor_keys[i], f, **kwargs)
            # all partial signatures; non-existent entries are represented
            # by all-zero bytes (which is not valid in BIP340)
            for i in range(self.context.n):
                for j in range(self.context.n):
                        BytesSerializer.stream_serialize(
                            self.partial_sigs[i][j], f, **kwargs)
            # all signature adaptors; there will be at most one
            # per signing session, i.e. per contributor
            for i in range(self.context.n):
                BytesSerializer.stream_serialize(
                    self.signature_adaptors[i], f, **kwargs)
            # all fidelity bond hashlock preimages
            for i in range(self.context.n):
                BytesSerializer.stream_serialize(
                    self.fb_hashlock_preimages[i], f, **kwargs)

    @classmethod
    def stream_deserialize(cls, f: ByteStream_Type, **kwargs: Any) -> bytes:
        """ Create an instance of PathCoinParticipantState from
        serialized data.
        """
        v_contribs = VectorSerializer.stream_deserialize(
            f, element_class=PathCoinContextContribution, **kwargs)
        assert isinstance(v_contribs[0], PathCoinContextContribution)
        n = len(v_contribs)
        outpoint = CMutableOutPoint.stream_deserialize(f, **kwargs)
        x = ser_read(f, 4)
        coin_amount = struct.unpack(b"<i", x)[0]
        spending_out = CTxOut.stream_deserialize(f, **kwargs)
        sPK = spending_out.scriptPubKey
        new_spending_out = CTxOut(coin_amount, sPK)
        master_timelock = struct.unpack(b"<i", ser_read(f, 4))[0]
        privkey = CKey(BytesSerializer.stream_deserialize(
            f, **kwargs))
        idx = struct.unpack(b"<i", ser_read(f, 4))[0]
        fb_spending_key = CKey(BytesSerializer.stream_deserialize(
            f, **kwargs))
        fb_hashlock_preimage = BytesSerializer.stream_deserialize(
            f, **kwargs)
        flag = f.read(1)
        funding = False
        if flag == b"\x00":
            v_nonces = None
        elif flag == b"\x01":
            funding = True
            v_nonces = []
            for _ in range(n):
                v_nonces.append(BytesSerializer.stream_deserialize(
                    f, **kwargs))
            nps = {}
            for i in range(n):
                nps[i] = []
                for _ in range(n):
                    nps[i].append(BytesSerializer.stream_deserialize(
                        f, **kwargs))
            adaptor_secret = BytesSerializer.stream_deserialize(
                f, **kwargs)
            v_adaptor_keys = []
            for i in range(n):
                v_adaptor_keys.append(CPubKey(BytesSerializer.stream_deserialize(
                    f, **kwargs)))
            partial_sigs = {}
            for i in range(n):
                partial_sigs[i] = []
                for j in range(n):
                    partial_sigs[i].append(BytesSerializer.stream_deserialize(
                        f, **kwargs))
            sig_adaptors = []
            for i in range(n):
                sig_adaptors.append(BytesSerializer.stream_deserialize(
                    f, **kwargs))
            fb_hashlock_preimages = []
            for i in range(n):
                fb_hashlock_preimages.append(BytesSerializer.stream_deserialize(
                    f, **kwargs))
        else:
            raise PathCoinParticipantStateDeserializationError()
        # Now create the context, and then use that to initialize the state object
        ctxt = PathCoinContext(n, coin_amount, master_timelock)
        for i, contrib in enumerate(v_contribs):
            ctxt.add_contribution(i, contrib)
        assert ctxt.scriptPubKey, PathCoinParticipantStateDeserializationError(
            "Failed to build full context, cannot build state.")
        inst = cls(idx, ctxt, v_contribs[idx].destination,
                   privkey=privkey, nonces=v_nonces,
                   fb_spending_key=fb_spending_key,
                   fb_hashlock_preimage=fb_hashlock_preimage)
        assert isinstance(inst, PathCoinParticipantState)
        #optional
        if funding:
            inst.context.outpoint = outpoint
            inst.context.spending_out = new_spending_out
            inst.context.set_spending_transactions()
            inst.nonce_points = nps
            inst.adaptor_secret = adaptor_secret
            inst.context.adaptor_keys = v_adaptor_keys
            inst.partial_sigs = partial_sigs
            inst.signature_adaptors = sig_adaptors
            inst.fb_hashlock_preimages = fb_hashlock_preimages
            # deserialization in the funding case requires
            # fully populated nonce matrix, so aggregates must
            # be recalculated
            inst.set_aggregate_Rs()
        return inst
        
    def save(self, funding=False) -> None:
        # Persist state to disk
        # TODO: carefully consider this issue with workflow:
        # we create all the partial sigs *before* actually funding the pathcoin,
        # but *after* creating the funding transaction (need txid etc.).
        # So we want to persist the nonce-state (see comments in stream_serialize),
        # but only once we are sure the pathcoin exists? i.e. it should be actually paid.
        with open(PATHCOIN_FILENAME_PREFIX + str(self.contrib_context.idx), "wb") as f:
            self.stream_serialize(f, funding=funding)

class PathCoinTransfer(Serializable):
    """ This object encapsulates the set of data passed from
    participant k to participant k+1.
    """
    def __init__(self, idx: int, adaptor: bytes, signatures: List[bytes],
                 fb_preimage: bytes=b""):
        # notice that it only makes sense to create this object with
        # a State object that has gone through "pre-sign", so that the
        # relevant partial signatures are present, and for participant
        # at index `k`, it should have already done a "receive" on state
        # sent to it by `k-1`, so that it has the extra partial signatures
        # from that.
        self.idx = idx
        self.adaptor = adaptor
        # each new participant, if their index is k, adds:
        # n -1 -k partial signatures (their own vertical slice in the matrix)
        # 1 adaptor (their own, i.e. adaptor for (k, k).
        self.partial_signatures = signatures
        self.fb_preimage = fb_preimage

    def stream_serialize(self, f: ByteStream_Type, **kwargs: Any) -> None:
        """ Serializes:
            1. index (int).
            2. list of partial signatures (bytes).
            3. adaptor (bytes).
            4. fidelity bond hash preimage (bytes).
            """
        f.write(struct.pack(b"<i", self.idx))
        for ps in self.partial_signatures:
            BytesSerializer.stream_serialize(ps, f, **kwargs)
        BytesSerializer.stream_serialize(self.adaptor, f, **kwargs)
        BytesSerializer.stream_serialize(self.fb_preimage, f, **kwargs)

    @classmethod
    def stream_deserialize(cls, f: ByteStream_Type, **kwargs: Any) -> None:
        if not "context_n" in kwargs:
            raise PathCoinParticipantStateDeserializationError(
                "Failed to deserialize transfer, n missing.")
        idx = struct.unpack(b"<i", ser_read(f, 4))[0]
        sigs = []
        for _ in range(kwargs["context_n"] - 1 - idx):
            sigs.append(BytesSerializer.stream_deserialize(f, **kwargs))
        adaptor = BytesSerializer.stream_deserialize(f, **kwargs)
        fb_preimage = BytesSerializer.stream_deserialize(f, **kwargs)
        return cls(idx, adaptor, sigs, fb_preimage=fb_preimage)

class PathCoinTransferAggregate(Serializable):
    """
    Due to the PathCoin mechanism, "transfer" is an aggregation process:
    the set of data that participant k+1 passes to k+2 is a superset
    of what k passed to k+1. This naturally suggests using a serialization
    that can be appended to, as here.    
    """
    def __init__(self, n: int, transfers: Union['PathCoinTransfer', None]=None):
        # notice that it only makes sense to create this object with
        # a State object that has gone through "pre-sign", so that the
        # relevant partial signatures are present, and for participant
        # at index `k`, it should have already done a "receive" on state
        # sent to it by `k-1`, so that it has the extra partial signatures
        # from that.
        self.n = n
        self.transfers = transfers
        if transfers is None:
            self.transfers = []
            self.add_this_transfer()

    def add_this_transfer(self, idx: int, adaptor: bytes, partial_sigs) -> None:
        # The partial sigs arg can be the full set of partial sigs in the
        # State object (for convenience we do the slicing here).
        self.transfers.append(PathCoinTransfer(idx, adaptor, partial_sigs[idx][idx+1:]))

    def save(self):
        idx = len(self.transfers) - 1
        fn = PATHCOIN_FILENAME_PREFIX + str(idx) + ".transfer"
        with open(fn, "wb") as f:
            f.write(b64encode(self.serialize()))
        print("Transfer file has been saved to: ", fn)

    @classmethod
    def read_from_file(cls, filename: str, idx: int):
        with open(filename, "rb") as f:
            data = b64decode(f.read())
        return cls.deserialize(data)

    def stream_serialize(self, f: ByteStream_Type, **kwargs: Any) -> None:
        """ Serializes the list of transfers, and `n`.
            """
        f.write(struct.pack(b"<i", self.n))
        VectorSerializer.stream_serialize(self.transfers, f, **kwargs)

    @classmethod
    def stream_deserialize(cls, f: ByteStream_Type, **kwargs: Any) -> None:
        n = struct.unpack(b"<i", ser_read(f, 4))[0]
        transfers = VectorSerializer.stream_deserialize(f,
                                    PathCoinTransfer, context_n=n, **kwargs)
        return cls(n=n, transfers=transfers)

# 1. create PathCoinContext
# 2. create PathCoinParticipantState (contains context and also secret keys)
# 3. create PathCoinSigner (will be able to do signing and aggregating actions using the above).
class PathCoinSigner(object):
    """ Represents the actor which does the signing
        and transferring of the pathcoin. Notice that this
        actor is stateless; you just provide state and callers
        are responsible for knowing if these signing actions
        are both needed, and safe to execute."""
    def __init__(self, state: PathCoinParticipantState):
        self.state = state

    def receive_partial_signature(self, contrib_idx: int, sig_idx: int, sig: bytes) -> bool:
        if not self.verify_partial_signature(contrib_idx, sig_idx, sig):
            return False
        self.state.partial_sigs[contrib_idx][sig_idx] = sig
        return True

    def set_all_partial_signatures(self) -> Tuple[List[bytes], bytes]:
        """ Called once all MuSig setups (phase1,2) are complete.
        Creates all partial signatures and adaptors for *this* index. """
        sigs = []
        for i in range(self.state.context.n):
            sigs.append(self.get_partial_signature(i))
        return (sigs, self.get_signature_adaptor())
 
    def get_aggregated_signature(self, signing_idx: int) -> bytes:
        """ Should be called only when all the partial signatures for session
        at signing_index have been collected (so e.g. it is possible immediately
        only for the first participant).
        Validity is implied by validity of each partial sig having been checked,
        combined with linearity, for the R value R_agg on the key P_agg.
        """
        s = 0
        for i in range(self.state.context.n):
            s += int_from_bytes(self.state.partial_sigs[signing_idx][i])
        s = s % GROUPN
        return bytes_from_int(s)

    def get_partial_signature(self, idx: int, include_t: bool = False) -> bytes:
        """ Returns partial signature in the form:
        s_i = k_i (-t_i) + H(R,P,m)H(L||P_i)x_i for this participant,
        and can only be calculated after the first two rounds are completed
        by all participants, so we know the full (and sign flipped)
        aggregate nonce.
        Note that: returning a signature *adaptor* just means
        returning a partial, but subtracting the secret t_i.
        """
        # Must only be attempted once the first two rounds are completed
        # by all the participants.

        # We calculate using actual arithmetic rather than using `schnorr_sign`,
        # because that algo doesn't account for musig nor adaptors.
        # NOTE: the complete insecurity of doing this is one reason this cannot
        # be used in prod. (One!).
        
        agg_priv_int = int_from_bytes(get_agg_x_i(
            [self.state.context.musig_pubkeys[i] for i in range(self.state.context.n)],
            self.state.signing_key,
            self.state.contrib_context.idx))
        if self.state.context.key_sign_flipped:
            # flipping agg_priv_int is the same as flipping the base signing key.
            # Note that the flip is done here because the Context object doesn't
            # own the private key, whereas the nonce flip is done inside the State object.
            agg_priv_int = GROUPN - agg_priv_int
        # Note that the context object, when constructed (including from serialization),
        # will have already flipped the sign of the nonce.
        my_nonce_int = int_from_bytes(self.state.nonces[idx])
        # x-only forms of keys are required for consensus:
        xonlyaggR = XOnlyPubKey(self.state.agg_Rs[idx])
        xonlyaggP = XOnlyPubKey(self.state.context.agg_P)
        e = int_from_bytes(bip340_signing_hash(bytes(xonlyaggR),
                    bytes(xonlyaggP),
                    self.state.context.get_sighash(idx))) % GROUPN
        # Some debug statements that are useful:
        #print("In get partial signature for signing session {}, calculating sighash using R: {}, P: {}, sighash: {}, and got e: {}".format(
        #    str(idx), hexlify(bytes(xonlyaggR)).decode(), hexlify(bytes(xonlyaggP)).decode(), hexlify(self.state.context.get_sighash(idx)).decode(),
        #    str(e)))

        # s = k + ex, or k + t + ex where needed:
        sig = (my_nonce_int + e * agg_priv_int) % GROUPN
        if include_t:
            if not self.state.adaptor_secret:
                raise PathCoinParticipantStateError("Cannot produce signature "
                                                    "adaptor because adaptor secret is missing.")
            adaptor_int = int_from_bytes(self.state.adaptor_secret)
            sig = (sig - adaptor_int) % GROUPN
        sig_bytes = bytes_from_int(sig)
        if include_t:
            # We don't set the partial signature, if we're returning
            # an adaptor (the only reason to set include_t = True)
            return sig_bytes
        self.state.partial_sigs[idx][self.state.contrib_context.idx] = sig_bytes
        # some more debug statements that are useful (if you need to audit the full calc.):
        #if idx == 0 and self.state.contrib_context.idx == 0:
        #    print("**WE CALCULATED PARTIAL SIG THUS: **:")
        #    if include_t:
        #        print("Used this t-value: {}, bytes: {}".format(adaptor_int, hexlify(self.state.adaptor_secret).decode()))
        #    print("For us: {} and for signing session: {}".format(self.state.contrib_context.idx, idx))
        #    print("k (pre-flipped): {}, e: {}, agg-x-i (flipped): {}, giving s: {}".format(hexlify(self.state.nonces[idx]).decode(),
        #            hexlify(bytes_from_int(e)).decode(), hexlify(bytes_from_int(agg_priv_int)).decode(), hexlify(sig_bytes).decode()))
        return sig_bytes

    def verify_partial_signature(self, partial_sig: bytes, contrib_idx: int,
                           sig_idx: int, include_t: bool = False) -> bool:
        """ Given a partial sig s_i (= k_i + H(..)x_agg_i) , which we can combine
        with pre-committed R_i, check if it verifies: s_iG =? R_i + eP_agg_i.
        Note we must flip signs of locally stored R partials, and P partials,
        if and only if (for each, separately), we have flipped the sign of
        the corresponding aggregate key.
        We also include the T value corresponding to index index, if it is set,
        into s_iG =?= R_i - T_i + eP_agg_i.
        """
        LHS = privkey_to_pubkey(partial_sig) # LHS=sG
        R = self.state.nonce_points[contrib_idx][sig_idx] #first participant, then signing session
        try:
            T = CPubKey(self.state.context.adaptor_keys[contrib_idx])
        except Exception as e:
            raise PathCoinParticipantStateError("Failed to parse adaptor key for index " + \
                                                str(contrib_idx) + " error: " + repr(e))
        # Yay, BIP340 sign flipping bullshit
        if self.state.nonce_sign_flipped[sig_idx]:
            R = flip_pubkey_sign(R)
        # note: if we are including t for an adaptor verify, we
        # do *not* need to sign flip in this version, because
        # this verification is only a delta to the pre-existing R, P
        # values and outputs a point for the verifier: sG (= (R+eP) - T)
        # which does *not* need to be of a certain parity.
        # x-only forms of keys are required for consensus:
        xonlyaggR = XOnlyPubKey(self.state.agg_Rs[sig_idx])
        xonlyaggP = XOnlyPubKey(self.state.context.agg_P)      
        e = bip340_signing_hash(bytes(xonlyaggR),
                    bytes(xonlyaggP),
                    self.state.context.get_sighash(sig_idx))
        #print("In verify for signing session {}, calculating sighash using R: {}, P: {}, sighash: {}, and got e: {}".format(
        #    str(sig_idx), hexlify(bytes(xonlyaggR)).decode(), hexlify(bytes(xonlyaggP)).decode(), hexlify(self.state.context.get_sighash(sig_idx)).decode(),
        #    int_from_bytes(e) % GROUPN))        
        P = get_agg_P_i([self.state.context.musig_pubkeys[i] for i in range(self.state.context.n)], contrib_idx)
        # as above
        if self.state.context.key_sign_flipped:
            P = flip_pubkey_sign(P)
        eP = tweak_multiply(e, P)
        RT = R
        if include_t:
            #print("Working with T: ", T)
            #print("Part of current set: ", self.state.context.adaptor_keys)
            RT = CPubKey.combine(CPubKey(RT), T.negated())
        #print("In final verif check by {} for sig from {} in signing session {}, comparing keys: {} and {}".format(
        #    self.state.contrib_context.idx, contrib_idx, sig_idx, LHS, jmbitcoin.add_pubkeys([RT, eP])))
        #if sig_idx == 0 and contrib_idx == 0:
            #print("**WE VERIFIED PARTIAL SIG THUS: **:")
            #print("From {} and for signing session: {}".format(contrib_idx, sig_idx))
            #print("R (pre-flipped): {}, e: {}, agg-P-i (flipped): {}, giving s: {}".format(RT,
            #        hexlify(e).decode(), P, hexlify(partial_sig).decode()))        
        return LHS == CPubKey.combine(CPubKey(RT), eP)

    def get_signature_adaptor(self) -> bytes:
        return self.get_partial_signature(idx= self.state.contrib_context.idx,
                                          include_t=True)

    def verify_signature_adaptor(self, sig_adaptor: bytes, contrib_idx: int,
                                 sig_idx: int) -> bool:
        return self.verify_partial_signature(sig_adaptor, contrib_idx,
                                             sig_idx, include_t=True)