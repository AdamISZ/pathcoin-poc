import io
import logging
import os
import sys
from configparser import ConfigParser, NoOptionError
from typing import Tuple
from bitcointx.wallet import CCoinAddress
from bitcointx import select_chain_params
from utils import EXIT_FAILURE, pcprint
from jsonrpc import JsonRpc


def lookup_appdata_folder(appname):
    """ Given an appname as a string,
    return the correct directory for storing
    data for the given OS environment.
    """
    if sys.platform == 'darwin':
        if "HOME" in os.environ:
            data_folder = os.path.join(os.environ["HOME"],
                                   "Library/Application support/",
                                   appname) + '/'
        else:
            pcprint("Could not find home folder")
            sys.exit(EXIT_FAILURE)

    elif 'win32' in sys.platform or 'win64' in sys.platform:
        data_folder = os.path.join(os.environ['APPDATA'], appname) + '\\'
    else:
        data_folder = os.path.expanduser(os.path.join("~", "." + appname + "/"))
    return data_folder

class AttributeDict(object):
    """
    A class to convert a nested Dictionary into an object with key-values
    accessibly using attribute notation (AttributeDict.attribute) instead of
    key notation (Dict["key"]). This class recursively sets Dicts to objects,
    allowing you to recurse down nested dicts (like: AttributeDict.attr.attr)
    """

    def __init__(self, **entries):
        self.currentnick = None
        self.add_entries(**entries)

    def add_entries(self, **entries):
        for key, value in entries.items():
            if isinstance(value, dict):
                self.__dict__[key] = AttributeDict(**value)
            else:
                self.__dict__[key] = value

    def __setattr__(self, name, value):
        if name == 'nickname' and value != self.currentnick:
            self.currentnick = value
            logFormatter = logging.Formatter(
                ('%(asctime)s [%(threadName)-12.12s] '
                 '[%(levelname)-5.5s]  %(message)s'))
            logsdir = os.path.join(os.path.dirname(
                global_singleton.config_location), "logs")
            fileHandler = logging.FileHandler(
                logsdir + '/{}.log'.format(value))
            fileHandler.setFormatter(logFormatter)
            log.addHandler(fileHandler)

        super().__setattr__(name, value)

    def __getitem__(self, key):
        """
        Provides dict-style access to attributes
        """
        return getattr(self, key)


global_singleton = AttributeDict()
global_singleton.APPNAME = 'pathcoin'
global_singleton.config = ConfigParser(strict=False)
#This is reset to a full path after load_program_config call
global_singleton.config_location = 'pathcoin.cfg'
#as above
global_singleton.commit_file_location = 'cmtdata/commitments.json'
global_singleton.wait_for_commitments = 0
# fidelity bonds are a bit higher than coin
# values to align incentives. This is the multiplier:
global_singleton.fidelity_bond_multiplier = 1.1
# uh .. no idea really what this number should be:
global_singleton.blockheight_window = 10

def pc_single() -> AttributeDict:
    return global_singleton

defaultconfig = \
    """
[BLOCKCHAIN]
# options: bitcoin-rpc, regtest, bitcoin-rpc-no-history, no-blockchain
# When using bitcoin-rpc-no-history remember to increase the gap limit to scan for more addresses, try -g 5000
# Use 'no-blockchain' to run the ob-watcher.py script in scripts/obwatch without current access
# to Bitcoin Core; note that use of this option for any other purpose is currently unsupported.
blockchain_source = regtest

# options: signet, testnet, mainnet
# Note: for regtest, use network = testnet
network = testnet

rpc_host = localhost
# default ports are 8332 for mainnet, 18443 for regtest, 18332 for testnet, 38332 for signet
rpc_port = 18443

# Use either rpc_user / rpc_password pair or rpc_cookie_file.
rpc_user = bitcoinrpc
rpc_password = 123456abcdef
#rpc_cookie_file =

# rpc_wallet_file is not currently used here, can leave blank.
rpc_wallet_file =

[NETWORK]
#Set the correct values for hidden services for each participant, after
#each has done an initial run with `--bootstrap`.
#onions = 6xapwqugm5i63625hqif45joly33h7nf63c6ecwr6feshybnkwiiutqd.onion,w3rdalnxdslp5yqnh36shhmturmycnzlw3lvdyyvljcguw52llgcxjad.onion,fypuvcanh2bqtm2s2kiakro2x2xxtkis3qgn5gl6t7gycxo5cawxzhyd.onion
# use this alternative (ports) if you are running on localhost, and specify `--no-tor` as an option:
onions=62444,62445,62446
"""

def get_network() -> str:
    """Returns network name"""
    return global_singleton.config.get("BLOCKCHAIN", "network")

def validate_address(addr: str) -> Tuple[bool, str]:
    try:
        # automatically respects the network
        # as set in select_chain_params(...)
        dummyaddr = CCoinAddress(addr)
    except Exception as e:
        return False, repr(e)
    # additional check necessary because python-bitcointx
    # does not check hash length on p2sh construction.
    try:
        dummyaddr.to_scriptPubKey()
    except Exception as e:
        return False, repr(e)
    return True, "address validated"

def load_program_config(config_path: str = "") -> None:
    global_singleton.config.readfp(io.StringIO(defaultconfig))
    if not config_path:
        config_path = lookup_appdata_folder(global_singleton.APPNAME)
    # we set the global home directory, but keep the config_path variable
    # for callers of this function:
    global_singleton.datadir = config_path
    pcprint("User data location: " + global_singleton.datadir, "info")
    if not os.path.exists(global_singleton.datadir):
        os.makedirs(global_singleton.datadir)
    # prepare folders for wallets and logs
    global_singleton.config_location = os.path.join(
        global_singleton.datadir, global_singleton.config_location)

    try:
        loadedFiles = global_singleton.config.read(
            [global_singleton.config_location])
    except UnicodeDecodeError:
        pcprint("Error loading `joinmarket.cfg`, invalid file format.",
            "info")
        sys.exit(EXIT_FAILURE)

    # Create default config file if not found
    if len(loadedFiles) != 1:
        with open(global_singleton.config_location, "w") as configfile:
            configfile.write(defaultconfig)
        pcprint("Created a new `pathcoin.cfg`. Please review and adopt the "
              "settings and restart.", "info")
        sys.exit(EXIT_FAILURE)

    # configure the interface to the blockchain on startup
    global_singleton.bc_interface = get_blockchain_interface_instance(
        global_singleton.config)

def load_test_config(**kwargs) -> None:
    if "config_path" not in kwargs:
        load_program_config(config_path=".", **kwargs)
    else:
        load_program_config(**kwargs)

##########################################################
## Returns a tuple (rpc_user: String, rpc_pass: String) ##
##########################################################
def _get_bitcoin_rpc_credentials(_config: ConfigParser) -> Tuple[str, str]:
    filepath = None

    try:
        filepath = _config.get("BLOCKCHAIN", "rpc_cookie_file")
    except NoOptionError:
        pass

    if filepath:
        if os.path.isfile(filepath):
            rpc_credentials_string = open(filepath, 'r').read()
            return rpc_credentials_string.split(":")
        else:
            raise ValueError("Invalid cookie auth credentials file location")
    else:
        rpc_user = _config.get("BLOCKCHAIN", "rpc_user")
        rpc_password = _config.get("BLOCKCHAIN", "rpc_password")
        if not (rpc_user and rpc_password):
            raise ValueError("Invalid RPC auth credentials `rpc_user` and `rpc_password`")
        return rpc_user, rpc_password

def get_blockchain_interface_instance(_config: ConfigParser):
    # todo: refactor joinmarket module to get rid of loops
    # importing here is necessary to avoid import loops
    from blockchain import BitcoinCoreInterface, \
        RegtestBitcoinCoreInterface
    source = _config.get("BLOCKCHAIN", "blockchain_source")
    network = get_network()
    testnet = (network == 'testnet' or network == 'signet')

    if source in ('bitcoin-rpc', 'regtest'):
        rpc_host = _config.get("BLOCKCHAIN", "rpc_host")
        rpc_port = _config.get("BLOCKCHAIN", "rpc_port")
        if rpc_port == '':
            if network == 'mainnet':
                rpc_port = 8332
            elif network == 'regtest':
                rpc_port = 18443
            elif network == 'testnet':
                rpc_port = 18332
            elif network == 'signet':
                rpc_port = 38332
            else:
                raise ValueError('wrong network configured: ' + network)
        rpc_user, rpc_password = _get_bitcoin_rpc_credentials(_config)
        rpc_wallet_file = _config.get("BLOCKCHAIN", "rpc_wallet_file")
        rpc = JsonRpc(rpc_host, rpc_port, rpc_user, rpc_password)
        if source == 'bitcoin-rpc': #pragma: no cover
            bc_interface = BitcoinCoreInterface(rpc, network,
                rpc_wallet_file)
            if testnet:
                select_chain_params("bitcoin/testnet")
            else:
                select_chain_params("bitcoin")
        elif source == 'regtest':
            bc_interface = RegtestBitcoinCoreInterface(rpc,
                rpc_wallet_file)
            print("Setting the chain params to regtest")
            select_chain_params("bitcoin/regtest")
        else:
            assert 0
    elif source == 'no-blockchain':
        bc_interface = None
    else:
        raise ValueError("Invalid blockchain source")
    return bc_interface


# TODO just put this in the global config var.
SPENDING_TX_FEE_SATS = 5000
COMMON_NSEQUENCE_VALUE = 0xffffffff - 1

# some regtest addresses:
#bcrt1q72mdaj9sppgc0uh4jcy4kv8kzqywtanqhqa6ve
#bcrt1q36d9g0yfp0n0ep6sdvg6kxkzxnje9lzhehvkes
#bcrt1q6w86ff4v3km5jhj79dwjr8wv6sfdmxawzzx47z

# filename prefix for state files
PATHCOIN_FILENAME_PREFIX = "pathcoinstate"
