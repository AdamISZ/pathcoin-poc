#!/usr/bin/env python

"""
WORKFLOW


The workflow has two main phases, and one recovery or punishment phase.

SETUP PHASE

 All parties are online (here using *.onions, or for testing on localhost with option --no-tor))
 and share: keys, hashes and partial signatures.
 Once all the non-secret data is shared, all parties will persist the state of the *potential* pathcoin
 to a file.
 This is split into two coordinated executions ("setup" and "presign") in this proof of concept, the idea
 being that the first user can fund the prepared musig taproot address once it's created. In a real situation:
 
 * this would actually be only one phase of interaction, not two
 * the first participant prepares their funding tx by selecting utxos automatically within the application,
   and prepares that unsigned transaction. Instead of directly funding, which should not be done until this phase
   is completed in entirety, so that the first participant has *all* the other participants' partial signatures
   on their own spending transaction.



 NORMAL OPERATION

 Transfer:
 Using the 'send' method, sender creates a *.transfer file. This can be sent to the receiver
 by any suitable method.
 Receiver must check that sender's fidelity bond has been funded before accepting the coin.
 (This can be done in advance, to avoid needing an internet connection to receive).

 Optional phase: 'reclaim'/PENALTY CLAIM
 If timeout is passed, execute 'reclaim': claim back own fidelity bond coin.
 If a member has received the coin, then, during the time they hold it, they
 can (periodically, or just before spending), check the blockchain to ensure
 that previous owners have not claimed it. If they have, execute 'penalty'
 processing: take adaptor secret from blockchain signature and create spending
 event from that member's fidelity bond.

"""

import json
from binascii import hexlify, unhexlify
from typing import Tuple, Callable
from hashlib import sha256
from base64 import b64decode
from twisted.protocols import basic
from twisted.internet import reactor, protocol, task
from twisted.application.internet import ClientService
from twisted.internet.endpoints import TCP4ClientEndpoint
from txtorcon.socks import TorSocksEndpoint
import bitcointx
# must be done *first* before importing anything else out of the lib:
bitcointx.set_custom_secp256k1_path("/usr/local/lib/libsecp256k1.so")
from bitcointx.core import (COutPoint, CTxIn, CTxOut,
                            CMutableTransaction, CTxInWitness)
from bitcointx.core.key import CPubKey, XOnlyPubKey, CKey
from bitcointx.wallet import CCoinAddress
from bitcointx.core.script import CScriptWitness
from utils import (utxostr_to_utxo, human_readable_transaction,
                   get_secret_from_spend)
from cli_support import get_runme_parser, get_help
from fidelitybonds import (create_fidelity_bond_reclaim_transaction,
                           create_fidelity_bond_penalty_tx)
from pathcoin import (PathCoinContextContribution,
                      PathCoinParticipantState, PathCoinSigner,
                      PathCoinContext, PathCoinTransfer,
                      PathCoinTransferAggregate)
port_base = 61529
hostname = "localhost"
ONION_VIRTUAL_PORT = 5321
# How many seconds to wait before treating an onion
# as unreachable
CONNECT_TO_ONION_TIMEOUT = 60
from config import (PATHCOIN_FILENAME_PREFIX, load_program_config,
                    pc_single, SPENDING_TX_FEE_SATS)
from hiddenservices import HiddenService

class PCMessage(object):
    """ Encapsulates the messages passed over the wire
    to and from other onion peers
    Simple message syntax:
    json of three keys 'session', 'type', 'line'.
    `type` is as per `msg_callbacks` in PathCoinManager.
    `session` is an integer allowing to differentiate multiple
    communications for the signing of different transactions, at once.
    Line is of this syntax:
    counterparty_index;val,val,..
    The `val`s are keys, partial sigs etc. All hex encoded.
    The index must be an integer, then colon, then comma separated `val`s.
    """
    def __init__(self, signing_session: int, index: int,
                 vals: Tuple[str], msgtype: int):
        self.signing_session = signing_session
        self.text = str(index) + ";" + ",".join(vals)
        self.msgtype = msgtype

    def encode(self) -> bytes:
        self.encoded = json.dumps({"session": self.signing_session,
                                   "type": self.msgtype,
                                   "line": self.text}).encode("utf-8")
        return self.encoded

    def get_vals(self):
        valstring = self.text.split(";")[1]
        return valstring.split(",")

    def get_counterparty_index(self) -> int:
        return int(self.text.split(";")[0])

    @classmethod
    def from_string_decode(cls, msg: bytes) -> 'PCMessage':
        """ Build a custom message from a json-ified string.
        """
        try:
            msg_obj = json.loads(msg)
            signing_session = msg_obj["session"]
            text = msg_obj["line"]
            msgtype = msg_obj["type"]
            assert isinstance(msgtype, int)
            assert isinstance(text, str)
            index, valstring = text.split(";")
            vals = valstring.split(",")
        except:
            print("Error decoding message")
            raise
        return cls(signing_session, index, vals, msgtype)

class PathCoinParticipant(object):
    """ Representing 1 party in N-party pathcoin,
    this object:
    - owns a PathCoinParticipantState object managing and
      persisting key/sig data for the pathcoin.
    - owns a PathCoinSigner object able to create and verify
      partial sigs and adaptors for the above State.
    - manages the network interaction between this
    participant and the other participants; all reachable
    network destinations must be passed as onion hostnames in
    the first argument to the constructor.
    """

    def __init__(self, onions: Tuple[str], state: PathCoinParticipantState,
                 coin_amount: int):
        self.myindex = myindex
        self.state = state
        # convenience:
        self.context = self.state.context
        self.signer = PathCoinSigner(state)
        # these manage instantiation of network communication
        # protocols, see PCLineProtocol
        self.factories = {}
        for i in range(self.context.n):
            if i == self.myindex:
                continue
            self.connect(i, onions[i])
        self.connected_counter = 0
        self.msg_callbacks = {1: self.receive_contrib_message,
                                  2: self.receive_funding_notification,
                                  3: self.receive_commitments,
                                  4: self.receive_nonces,
                                  5: self.receive_initial_partials}
        self.contribs_sent = False
        self.setup_loop = None

    def onion_hostname_callback(self, hostname):
        """ Just informational; allows bootstrapping,
        by printing the hostname.
        """
        print("We are starting a hidden service at: ", hostname)

    def start_key_exchange(self):
        # current simple model: index 0 is always initiator
        if not self.myindex == 0:
            return
        pass
        for i in range(self.context.n):
            if i == self.myindex:
                continue
            self.send_contribution_message(i)

    def send_contribution_message(self, idx: int):
        
        msg = PCMessage(idx, self.state.contrib_context.idx,
                        (hexlify(self.state.contrib_context.serialize()).decode(),), 1)
        self.send(idx, msg)

    def register_connection(self):
        """ This code is naively optimistic; if we registered
        all the connections, we assume they're all up.
        """
        self.connected_counter += 1
        print("We have connected to", self.connected_counter, "participants.")
        if self.connected_counter == self.context.n - 1 and self.mode == "setup":
            self.start_key_exchange()

    def register_disconnection(self):
        self.connected_counter -= 1
        pass

    def connect(self, index: int, onion: str) -> None:
        # allows a bootstrap, where connect is a no-op:
        if onion == "":
            return
        if index in self.factories:
            return
        self.factories[index] = PCLineClientFactory(self.receive_message,
        self.register_connection, self.register_disconnection)
        if not onion.endswith("onion"):
            # testing mode using localhost:
            self.tcp_connector = reactor.connectTCP("127.0.0.1", int(onion),
                                                    self.factories[index])
        else:
            torEndpoint = TCP4ClientEndpoint(reactor, "localhost",
                                             9050,
                                             timeout=CONNECT_TO_ONION_TIMEOUT)
            onionEndpoint = TorSocksEndpoint(torEndpoint, onion,
                                             ONION_VIRTUAL_PORT)
            self.reconnecting_service = ClientService(onionEndpoint, self.factories[index])
            #print("Now trying to connect to : " + onion + str(ONION_VIRTUAL_PORT))
            self.reconnecting_service.startService()

    def send(self, counterparty_index: int, msg: PCMessage):
        res = self.factories[counterparty_index].send(msg)
        if not res:
            #print("Failed to send to {}, message was: {}".format(
            #    counterparty_index, msg.text))
            # keep trying in case connection drops happen:
            reactor.callLater(4.0, self.send, counterparty_index, msg)

    def receive_message(self, message: PCMessage):
        """ This sends the message to the right callback,
        dependent on the message type. Note that this code,
        being only for toy/test cases, doesn't bother to
        pay attention to network source, just trusts the
        counterparty to be sending a consistent index to
        update the right set of keys, nonces, sigs etc.
        """
        # Just ignore all messages that don't specify our
        # signing context
        msgtype = message.msgtype
        if msgtype in self.msg_callbacks.keys():
            self.msg_callbacks[msgtype](message)
            return
        print("Received message of unknown message type: ", msgtype)

    def receive_contrib_message(self, msg: PCMessage) -> None:
        index = msg.get_counterparty_index()
        assert index != self.myindex
        try:
            contrib = PathCoinContextContribution.deserialize(
                unhexlify(msg.get_vals()[0]))
            self.state.set_context_contribution(index, contrib)
        except Exception as e:
            print(repr(e))
            print("Failed to parse context contribution message: ", msg)
            return
        if not self.contribs_sent:
            for i in range(self.context.n):
                if i == self.myindex:
                    continue
                self.send_contribution_message(i)
            self.contribs_sent = True
        if self.mode == "setup":
            if self.setup_loop is None:
                self.setup_loop = task.LoopingCall(self.finish_setup)
                self.setup_loop.start(2.0)

    def finish_setup(self):
        if not len(self.context.contribs.keys()) == self.context.n:
            return
        if self.setup_loop.running:
            self.setup_loop.stop()
        # A fully initialized context allows us to create the fidelity
        # bond scriptPubKeys:
        self.state.set_fidelity_bond_txout()
        print("Our fidelity bond address is: ", CCoinAddress.from_scriptPubKey(
            self.state.fidelity_bond_txout.scriptPubKey))
        print("The funding address is: ", self.context.get_address())
        self.state.save()
        # can't shut down because we might not have sent our own contribs out yet:
        #reactor.stop()

    def send_funding_message(self, utxostr: str):
        """ Only ever sent by "Alice", hence hardcoded 0 indices."""
        msg = PCMessage(0, 0,(utxostr,), 2)
        for idx in range(1, self.context.n):
            self.send(idx, msg)
        self.receive_funding_notification(msg)

    def receive_funding_notification(self, msg: PCMessage):
        """ As above, we just assume that the *sender* is Alice,
        the receiver can be any participant.
        """
        utxostr = msg.get_vals()[0]
        success, txidn = utxostr_to_utxo(utxostr)
        if not success:
            raise Exception("Failed to parse utxo")
        self.state.set_funding_event(utxostr)
        for i in range(self.context.n):
            if i == self.state.contrib_context.idx:
                continue
            self.send_commitment_exchange_message(i) 

    def send_commitment_exchange_message(self, i: int) -> None:
        """ Sending to participant i, the nonce commitment
        for all siging sessions, from us (participant idx).
        Notice that in total, ~N^2 messages are sent over
        the wire (~N from each)."""
        msg = PCMessage(0, # signing session is ignored, we send for all signing sessions
                        self.state.contrib_context.idx,
                        (hexlify(x).decode() for x in 
                         self.state.nonce_hashes[self.state.contrib_context.idx]), 3)
        self.send(i, msg)

    def receive_commitments(self, msg: PCMessage):
        """ This is the receipt of message 1
        """
        index = msg.get_counterparty_index()
        assert index != self.myindex
        try:
            comms = [unhexlify(x) for x in msg.get_vals()]
        except:
            print("Failed commitment exchange message: ", msg)
            return
        complete = self.state.set_nonce_commitments(index, True, comms)
        if complete:
            self.send_nonce_exchange_messages()

    def send_nonce_exchange_messages(self):
        msg = PCMessage(0, self.state.contrib_context.idx,
                        (hexlify(x).decode() for x in
                         self.state.nonce_points[self.state.contrib_context.idx]), 4)
        for i in range(self.context.n):
            if i == self.state.contrib_context.idx:
                continue
            self.send(i, msg)

    def receive_nonces(self, msg: PCMessage):
        """ This is the receipt of message 2
        """
        index = msg.get_counterparty_index()
        assert index != self.myindex
        try:
            for R in (unhexlify(x) for x in msg.get_vals()):
                R = CPubKey(unhexlify(msg.get_vals()[0]))
        except:
            print("Failed nonce exchange message: ", msg)
            return
        complete = self.state.set_nonce_commitments(
            idx=index, nonce_points=[unhexlify(x) for x in msg.get_vals()])
        if complete:
            # set aggregate Rs will have been called, we are ready to sign.
            # TODO : code all the signatures that need to be created here.
            # Then code the sending of the correct subset to each counterparty.
            self.state.set_all_my_partial_signatures(*self.signer.set_all_partial_signatures())
            self.send_initial_partial_signatures()

    def send_initial_partial_signatures(self):
        """ Prepare the set of partial signatures that must be initially
        sent to each counterparty, then send one message to each."""
        j = self.state.contrib_context.idx
        # take the sigs for *each* signing session before my index, and provide my sig for that:
        partial_sigs_to_send = [self.state.partial_sigs[x][j] for x in range(j)]
        if len(partial_sigs_to_send) == 0:
            print("We have no sigs to send, so not sending partial signatures message.")
            return
        for k in range(self.context.n): # participant
            if k == j:
                continue # not including me
            # the signing session index is irrelevant here as the message
            # spans several signing sessions:
            msg = PCMessage(0, j, (hexlify(x).decode() for x in partial_sigs_to_send), 5)
            self.send(k, msg)

    def receive_initial_partials(self, msg: PCMessage):
        """ Completes the initial state of the pathcoin, ready for
        spending events, once the partial signatures of all
        n participants have been received and verified.
        """
        # This is the endpoint of the initial negotation with a
        # single counterparty. To validate the partial signatures
        # they send us, we have to know *all* the nonces for each
        # signing session that they are providing partial sigs for.
        # However it's possible for us to reach this point with
        # counterparty X while counterparty Y has not yet sent us our
        # nonces, and that means we can't correctly aggregate the nonce
        # to verify the partial signature.
        # For this reason we delay the processing of this, until we
        # have a full set of nonces.
        if not self.state.all_nonces_complete:
            reactor.callLater(1.0, self.receive_initial_partials, msg)
            return
        index = msg.get_counterparty_index()
        assert index != self.myindex
        partial_sigs = [unhexlify(x) for x in msg.get_vals()]
        failed = False
        for i, ps in enumerate(partial_sigs):
            # before persisting, we must verify that each one is valid:
            # first argument is participant, second is signing session
            if not self.signer.verify_partial_signature(ps, index, i):
                print("Invalid partial signature from {} received by {}".format(
                    index, self.state.contrib_context.idx))
                failed = True
            self.state.partial_sigs[i][index] = ps
        if failed:
            return
        # if we have the full set that we expect on initialization,
        # note that this is the case:
        # examine *our* signing session and check that all sigs are
        # present (though, our own one, will not have been sent):
        if len(self.state.partial_sigs[
            self.state.contrib_context.idx]) == self.context.n:
            self.set_coin_fully_initialized()

    def set_coin_fully_initialized(self):
        self.state.save(funding=True)
        print("The pathcoin state file now contains the full information required "
              "to keep track of the coin. The initiator should fund it at the "
              "address: {}. The pathcoin is now ready to use.".format(self.context.get_address()))
        #reactor.stop()

    def transfer_coin(self):
        """ Creates a new file (*.transfer) containing a base64 TODO encoding
        of the data to be given by us to the next participant,
        to effect transfer of funds. This consists of:
        1. a (verifiable) signature adaptor for our partial signature
        for our signing session, at our index, such that the adaptor
        secret - which corresponds to the fidelity bond - will be revealed
        if we spend using that signing session.
        2. Our partial signatures for their own signing session, and all
        the succeeding signing sessions.
        3. Our hashlock secret for all fidelity bonds for participants preceding
        us, so that we can claim any fidelity bonds unlocked by spends of preceding
        signing sessions.
        4. (Optional?) For convenience, including utxo information about the fidelity
           bond, so the receiver can check funds were actually committed.
        For this toy version of the code, we will not attempt to handle the
        "toxic waste signature" problem, which will be that (a) you must delete the
        signature for your own signing session when you know the money has been transferred,
        but (b) you must *not* delete it, before you're sure the receiver has accepted!
        Here we just write the transfer to a file and optionally allow a network
        message to pass it, also.
        """
        # Message content: our adaptor on our signing session at our index.

        idx = self.state.contrib_context.idx
        signer = PathCoinSigner(self.state)
        adaptor = signer.get_signature_adaptor()
        # before sending it, check that at least *we* think it's a valid
        # adaptor!
        if not signer.verify_signature_adaptor(adaptor, idx, idx):
            print("Oops we do not validate our own adaptor!")
            return
        sigs_to_transfer = []
        for signing_session in range(idx+1, self.context.n):
            sigs_to_transfer.append(self.state.partial_sigs[signing_session][idx])
        # if we are index 1 or higher, we need to send a hashlock preimage also:
        if idx >=1:
            fb_preimage = self.state.fb_hashlock_preimage
        else:
            fb_preimage = b""
        tfr = PathCoinTransfer(idx, adaptor, sigs_to_transfer, fb_preimage=fb_preimage)
        # special case for index 0: no .transfer files not exits, we create from sratch.
        if idx == 0:
            agg = PathCoinTransferAggregate(self.context.n, [tfr])
            agg.save()
        else:
            # To create a file to give to k+1, we, as k, must read k-1
            # and update the object to save it to k.
            with open(PATHCOIN_FILENAME_PREFIX + str(idx-1) + ".transfer", "rb") as f:
                agg = PathCoinTransferAggregate.stream_deserialize(f)
            agg.transfers.append(tfr)
            agg.save()

    def receive_coin(self, fn: str):
        with open(fn, "rb") as f:
            aggser = b64decode(f.read())
        agg = PathCoinTransferAggregate.deserialize(aggser)
        # run checks on the "full partial signatures" and the adaptors
        # in the file that you've received; if they all verify at the
        # right index, then congratulations, you are now a proud owner
        # of a pathcoin.
        # Check 1: For each transfer in the aggregate, check the partial signatures
        # from idx+1 to n-1:
        assert isinstance(agg, PathCoinTransferAggregate)
        if len(agg.transfers) != self.state.contrib_context.idx:
            print("We expected {} Transfer objects, but we received {}.".format(
                self.state.contrib_context.idx, len(agg.transfers)))
            return
        for i, tfr in enumerate(agg.transfers):
            assert isinstance(tfr, PathCoinTransfer)
            for j, ps in enumerate(tfr.partial_signatures):
                if not self.signer.verify_partial_signature(ps, i, i+1+j):
                    print("Partial signature from contributor {} for signing session {} did not validate.".format(i, i+1+j))
                    return
                state.partial_sigs[i+1+j][i] = ps
            # Check 2: the adaptor for their own index must also verify:
            if not self.signer.verify_signature_adaptor(tfr.adaptor, i, i):
                print("Adaptor signature from contributor {} did not validate.".format(i))
                return
            else:
                print("Adaptor signature {} from contributor {} did validate.".format(hexlify(tfr.adaptor).decode(),i))
            state.signature_adaptors[i] = tfr.adaptor
            # Check 3 is that the fidelity bond secret matches. This is only required
            # for participants after the first two (the second participant only needs the
            # adaptor of the initiator for safety).
            if i >= 1:
                purported_hash_lock = sha256(tfr.fb_preimage).digest()
                if not purported_hash_lock == state.context.fb_hashlocks[i]:
                    print("hashlock secret provided: {} does not match "
                          "the hashlock in the script: {}".format(
                              hexlify(tfr.fb_preimage).decode(),
                              hexlify(state.context.fb_hashlocks[i]).decode()))
                    return
                else:
                    print("hashlock secret provided: {} does match "
                          "the hashlock in the script: {}".format(
                              hexlify(tfr.fb_preimage).decode(),
                              hexlify(state.context.fb_hashlocks[i]).decode()))
                state.fb_hashlock_preimages[i] = tfr.fb_preimage
        # Persist the new secret data, so we can use it to make a penalty claim if
        # we need to:
        state.save(funding=True)
        # All checks verified, at every expected index, we now have full control of the
        # pathcoin.
        print("Congratulations, you are now the owner of the pathcoin of value {} "
              "at address {}, with utxo: {}. You can either spend it any time using "
              "method 'spend', or transfer it to the next person using 'send'.".format(
                  self.context.spending_out.nValue, self.context.get_address(), self.context.outpoint))       

class PCLineProtocol(basic.LineReceiver):
    # TODO: line limit length
    MAX_LENGTH = 40000

    def connectionMade(self):
        self.factory.register_connection(self)
        basic.LineReceiver.connectionMade(self)

    def connectionLost(self, reason):
        self.factory.register_disconnection(self)
        basic.LineReceiver.connectionLost(self, reason)

    def lineReceived(self, line: bytes) -> None:
        try:
            msg = PCMessage.from_string_decode(line)
        except:
            print("Received invalid message: {}, "
                      "dropping connection.".format(line))
            self.transport.loseConnection()
            return
        self.factory.receive_message(msg, self)

    def message(self, message: PCMessage) -> None:
        self.sendLine(message.encode())

class PCLineFactory(protocol.ServerFactory):
    """ This factory allows us to start up instances
    of the LineReceiver protocol that are instantiated
    towards us.
    """
    protocol = PCLineProtocol

    def __init__(self, client):
        self.client = client

    def receive_message(self, message: PCMessage,
                        p: PCLineProtocol) -> None:
        self.client.receive_message(message)

    def register_connection(self, p: PCLineProtocol) -> None:
        pass

    def register_disconnection(self, p: PCLineProtocol) -> None:
        pass

class DummyClient(object):
    """ do nothing protocol client to allow hidden service bootstrap
    """
    def receive_message(self, message, p):
        pass
    def onion_hostname_callback(self, hostname):
        """ Just informational; allows bootstrapping,
        by printing the hostname.
        """
        print("Started a hidden service at: ", hostname)
class PCLineClientFactory(protocol.ReconnectingClientFactory):
    """ We define a distinct protocol factory for outbound connections.
    """
    protocol = PCLineProtocol

    def __init__(self, message_receive_callback: Callable,
                 connection_callback: Callable,
                 disconnection_callback: Callable):
        self.proto_client = None
        # callback takes MS3AMessage as arg and returns None
        self.message_receive_callback = message_receive_callback
        # connection callback, no args, returns None
        self.connection_callback = connection_callback
        # disconnection the same
        self.disconnection_callback = disconnection_callback        

    def clientConnectionLost(self, connector, reason):
        pass
        #print('MS3A client connection lost: ' + str(reason))

    def clientConnectionFailed(self, connector, reason):
        #print('MS3A client connection failed: ' + str(reason))
        if reactor.running:
            protocol.ReconnectingClientFactory.clientConnectionFailed(self,
                                                            connector, reason)        
    
    def register_connection(self, p: PCLineProtocol) -> None:
        self.proto_client = p
        self.connection_callback()

    def register_disconnection(self, p: PCLineProtocol) -> None:
        self.proto_client = None
        self.disconnection_callback()

    def send(self, msg: PCMessage) -> bool:
        # we may be sending at the time the counterparty
        # disconnected
        if not self.proto_client:
            return False
        self.proto_client.message(msg)
        return True

    def receive_message(self, message: PCMessage,
                        p: PCLineProtocol) -> None:
        self.message_receive_callback(message)

options, args = get_runme_parser()
# Sets these strings all to "", to bootstrap: your onion hostname will be printed (just *.onion, no port).
# Then, after exchanging these strings with your counterparties, run without `--bootstrap` option
# For non-tor usage, set the onions to localhost ports and specify `--no-tor` on the command line.
# TODO put it in the config file

if options.bootstrap:
    onions = ["", "", ""]
    method = "nomethod"
    myindex = args[0]
    x = DummyClient()
else:
    method = args[0]
    if method == "help":
        get_help(args[1])
        exit(0)
    myindex = int(args[1])
    ncounterparties = int(args[2])
    coin_amount = int(args[3])

    load_program_config()

    onionstr = pc_single().config.get("NETWORK", "onions")
    onions = onionstr.split(",")
    assert len(onions) == ncounterparties, "you must provide exactly one onion address per counterparty"

if method == "setup":
    my_destination = args[4]
    my_sPK = CCoinAddress(my_destination).to_scriptPubKey()    
    master_timelock = int(args[5])
    context = PathCoinContext(ncounterparties, coin_amount, master_timelock)
    state = PathCoinParticipantState(myindex, context, my_sPK)
    x = PathCoinParticipant(onions, state, coin_amount)
    x.mode = method

if method in ["presign", "send", "spend", "receive", "reclaim", "penalty"]:
    with open(PATHCOIN_FILENAME_PREFIX + str(myindex), "rb") as f:
        state = PathCoinParticipantState.stream_deserialize(f)
    x = PathCoinParticipant(onions, state, coin_amount)
    x.mode = method

if method == "presign" and myindex == 0:
    my_utxo_str = args[4]
    x.send_funding_message(my_utxo_str)

if method == "send":
    x.transfer_coin()

if method == "receive":
    # TODO this method only validates the adaptor
    # and partial signatures given by sender, in the file.
    # The user either manually has to check that all
    # preceding fidelity bonds were funded, or,
    # we can include the ability to check that on the blockchain
    # here, as an option.
    x.receive_coin(args[4])

if method == "spend":
    # pays out directly on the pathcoin with musig:
    vin = [CTxIn(state.context.outpoint)]
    vout = [CTxOut(nValue=state.context.coin_amount - SPENDING_TX_FEE_SATS,
                   scriptPubKey=state.context.destination_scriptPubKeys[
                       state.contrib_context.idx])]
    tx = CMutableTransaction(vin, vout, nVersion=2)
    # we do keypath spending on the negotiated musigpubkey.
    # the sig consists of the Xonly R_agg followed by the sum of the s values.
    # and the sighash was set earlier in pre-sign.
    signer = PathCoinSigner(state)
    s = signer.get_aggregated_signature(state.contrib_context.idx)
    # manually reconstruct a valid BIP340 signature; notice this is the
    # only place we have to do this, due to using MuSig; for OP_CHECKSIG
    # cases the underlying library adds the 'R' value for us.
    xonlyaggR = XOnlyPubKey(state.agg_Rs[state.contrib_context.idx])
    rs = xonlyaggR + s
    tx.wit.vtxinwit[0] = CTxInWitness(CScriptWitness([rs]))
    print(human_readable_transaction(tx))

if method == "reclaim":
    outpoint_str = args[4]
    payout_address = args[5]
    payout_sPK = CCoinAddress(payout_address).to_scriptPubKey()
    success, txidout = utxostr_to_utxo(outpoint_str)
    assert success, "Invalid utxo string"
    txid, outindex = txidout
    outpoint = COutPoint(txid[::-1], outindex)
    signed_tx = create_fidelity_bond_reclaim_transaction(outpoint,
                                             payout_sPK,
                                             state.context.coin_amount,
                                             state.context.n,
                                             state.contrib_context.idx,
                                             [state.context.fb_spending_keys[i] for i in range(state.context.n)],
                                             state.context.master_timelock,
                                             state.context.adaptor_keys[state.contrib_context.idx],
                                             [state.context.fb_hashlocks[i] for i in range(state.context.n)],
                                             state.context.get_final_fb_destination(),
                                             state.fb_spending_key)

    print(human_readable_transaction(signed_tx))
    success = pc_single().bc_interface.pushtx(signed_tx.serialize())
    msg = "Broadcast successful" if success else "Broadcast failed"
    print(msg)

if method == "penalty":
    idx_claiming_from = int(args[4])
    outpoint_str = args[5]
    payout_address = args[6]
    illegal_spend_tx = args[7]
    payout_sPK = CCoinAddress(payout_address).to_scriptPubKey()
    success, txidout = utxostr_to_utxo(outpoint_str)
    assert success, "Invalid utxo string"
    txid, outindex = txidout
    outpoint = COutPoint(txid[::-1], outindex)
    # TODO: get_secret_from_spend will take a tx from the blockchain interface
    # (for now we pass it on the command line in args[7])
    # Then:
    #
    # extract the signature from the witness, and compare it with a recorded
    # adaptor to get the adaptor secret, which we need for our penalty. We also
    # have to refer to the list of partial signatures for this signing session,
    # recorded in our state file:
    other_partial_signatures = []
    for i in range(state.context.n):
        if i == idx_claiming_from:
            continue
        other_partial_signatures.append(state.partial_sigs[idx_claiming_from][i])
    # dumping out a lot of intermediate data for the penalty. TODO change to actual
    # logging!
    print("About to calculate adaptor secret. We are penalising index: ", idx_claiming_from)
    print("For their signing index, we have these partial signatures: ",
          state.partial_sigs[idx_claiming_from])
    print("And we are passing through this list of partial sigs to get_secret: ",
          [hexlify(x) for x in other_partial_signatures])
    print("We had stored this list of adaptor keys: ", state.context.adaptor_keys)
    state.register_illegal_adaptor_usage(get_secret_from_spend(illegal_spend_tx,
                                        state.signature_adaptors[idx_claiming_from],
                                        state.context.adaptor_keys[idx_claiming_from],
                                        other_partial_signatures=other_partial_signatures,
                                        inidx=0), #TODO tx could spend it from a different input index
                                        idx=idx_claiming_from)
    signed_txs = create_fidelity_bond_penalty_tx(idx_claiming_from, outpoint,
                                             payout_sPK,
                                             state.context.coin_amount,
                                             state.context.n,
                                             state.contrib_context.idx,
                                             [state.context.fb_spending_keys[i] for i in range(state.context.n)],
                                             state.context.master_timelock,
                                             state.context.adaptor_keys[idx_claiming_from],
                                             [state.context.fb_hashlocks[i] for i in range(state.context.n)],
                                             state.context.get_final_fb_destination(),
                                             state.fb_spending_key,
                                             CKey.from_secret_bytes(state.adaptor_secrets[idx_claiming_from]) # set by `register_illegal`
                                             )
    print(*[human_readable_transaction(x) for x in signed_txs])

if options.testing:
    reactor.listenTCP(int(onions[myindex]), PCLineFactory(x))
else:
    hs = HiddenService(PCLineFactory(x), print,
                                          print,
                                          x.onion_hostname_callback,
                                          "localhost",
                                          9051,
                                          "127.0.0.1",
                                          8080,
                                          virtual_port=ONION_VIRTUAL_PORT,
                                          shutdown_callback=print,
                                          hidden_service_dir="hidserv" + str(myindex))
    # this call will start bringing up the HS; when it's finished,
    # it will fire the `onion_hostname_callback`.
    hs.start_tor()

reactor.run()

