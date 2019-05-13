# nbc/wallet: wallet APP for NBC coin, for details please visit http://nb-coin.com/
# Copyright (C) 2018 Wayne Chan. Licensed under the Mozilla Public License,
# Please refer to http://mozilla.org/MPL/2.0/

import sys, os, time, struct, traceback
from threading import Timer
from binascii import hexlify, unhexlify

from smartcard.CardConnectionObserver import ConsoleCardConnectionObserver
from smartcard.CardMonitoring import CardMonitor, CardObserver

from smartcard.sw.ErrorChecker import ErrorChecker
from smartcard.sw.ErrorCheckingChain import ErrorCheckingChain
from smartcard.sw.ISO7816_4ErrorChecker import ISO7816_4ErrorChecker
from smartcard.sw.ISO7816_8ErrorChecker import ISO7816_8ErrorChecker
from smartcard.sw.SWExceptions import SWException, WarningProcessingException

from smartcard.util import toHexString, toBytes

VERBOSE = '--verbose' in sys.argv
sys.ps1 = '\n>>>'

SELECT = toBytes('00A40400 0E D196300077130010000000020101')
GET_RESPONSE = [0x00, 0xc0, 0, 0]

gCard = None
gExpectedAtr  = toBytes("3B9F 00 801F038031E073FE211367 00 434F537EC101 00")
gExpectedMask = toBytes("FFFF 00 FFFFFFFFFFFFFFFFFFFFFF 00 FFFFFFFFFFFF 00")

gLastErrCode = '9000'

def checkAtrMatch(atr):
  if len(atr) != len(gExpectedAtr):
    return False
  
  for (targ,curr,mask) in zip(gExpectedAtr,atr,gExpectedMask):
    if targ != (curr & mask):
      return False
  return True  

class MyErrorChecker(ErrorChecker):
  def __call__(self, data, sw1, sw2):
    global gLastErrCode
    gLastErrCode = '%02x%02x' % (sw1,sw2)

gErrorchain = []
gErrorchain = [ ErrorCheckingChain(gErrorchain, MyErrorChecker()),
                ErrorCheckingChain(gErrorchain, ISO7816_8ErrorChecker()),
                ErrorCheckingChain(gErrorchain, ISO7816_4ErrorChecker()) ]

class DFTELECOMObserver(CardObserver):
  def __init__(self):
    self.observer = ConsoleCardConnectionObserver()
  
  def update(self, observable, actions):
    global gCard
    
    (addedcards, removedcards) = actions
    for card in addedcards:
      if checkAtrMatch(card.atr):
        card.connection = card.createConnection()
        card.connection.connect()
        if VERBOSE:
          card.connection.addObserver(self.observer)
        
        response, sw1, sw2 = card.connection.transmit(SELECT)
        if sw1 == 0x61:
          second, sw1, sw2 = card.connection.transmit(GET_RESPONSE + [sw2])
          response += second
        
        if sw1 == 0x90 and sw2 == 0x00:
          card.connection.setErrorCheckingChain(gErrorchain)
          gCard = card
          
          print('card added :',toHexString(card.atr).lower())
          print('card reader:',card.connection.getReader())
          
          Timer(4, lambda:autoStartCard() ).start()  # autoStartCard() will be called after 4 seconds
          break  # just select first expected card
    
    for card in removedcards:
      if checkAtrMatch(card.atr):
        if gCard:
          print('card removed:',toHexString(card.atr).lower())
        gCard = None

def transmit(s, conn=None):
  global gLastErrCode
  
  if not conn: conn = gCard.connection
  if type(s) == str: s = toBytes(s)  
  
  res, sw1, sw2 = conn.transmit(s); iLoop = 0
  while sw1 == 0x61 and iLoop < 32:   # max hold 8,192 bytes (32*256)
    second, sw1, sw2 = conn.transmit(GET_RESPONSE + [sw2])  # if sw2 == 0 means auto length
    res += second
    iLoop += 1
  
  return (res, '%02x%02x' % (sw1,sw2))

def getPubAddr(conn=None):
  try:
    res, status = transmit('80220200 02 0000',conn)
    if status == '9000':
      return ''.join(chr(c) for c in res)
  except:
    if gLastErrCode == '6984':  # no account exists yet
      return None
    else: raise    # re-raise
  return None

def getPubKey(conn=None):
  try:
    res, status = transmit('80220000 00',conn)
    if status == '9000':
      return ''.join(('%02x' % c) for c in res)
  except:
    if gLastErrCode == '6984':  # no account exists yet
      return None
    else: raise    # re-raise
  return None

def getPubKeyHash(conn=None):
  try:
    res, status = transmit('80220100 00',conn)
    if status == '9000':
      return ''.join(('%02x' % c) for c in res)
  except:
    if gLastErrCode == '6984':  # no account exists yet
      return None
    else: raise    # re-raise
  return None

def getSerialNo(conn=None):
  res, status = transmit('80010500 00',conn)
  if status == '9000':
    return ''.join(('%02x' % c) for c in res)
  else: return '00' * 8

monitor = CardMonitor()
observer = DFTELECOMObserver()
monitor.addObserver(observer)  # monitor.obs should be [observer]

#=====================

import getpass, hashlib

from nbc import util
from nbc import coins

from mine_client import PoetClient

curr_coin = coins.Newborntoken
curr_coin.WEB_SERVER_ADDR = 'http://user1-node.nb-chain.net'

MINING_NODE_ADDR = ('user1-node.nb-chain.net',30302)

if '--pool' in sys.argv and sys.argv[-1] != '--pool':
  _pool_addr = sys.argv[sys.argv.index('--pool')+1].split(':')
  if len(_pool_addr) >= 2:
    _pool_addr[1] = int(_pool_addr[1])
  else: _pool_addr.append(30302)
  MINING_NODE_ADDR = tuple(_pool_addr[:2])


gStartTime = time.time()
gBehavior  = 0

gPoetClient = None
gPseudoWallet = None

def inputPin():
  psw = ''
  while True:
    psw = getpass.getpass('input PIN: ').strip()
    if not psw:
      print('no password, operation will be cancel.')
      break
    if re.match(r'^\d+$',psw) and len(psw) >= 3 and len(psw) <= 10:
      break
    print("invalid PIN code, it should be 3-10 character of '0'-'9'")
  
  if psw and (len(psw) & 0x01) == 1: psw += 'f'
  return psw

class TeeMiner(object):
  SUCC_BLOCKS_MAX = 256
  
  def __init__(self, pubHash):
    self.pub_keyhash = pubHash
    self.succ_blocks = []
  
  def check_elapsed(self, block_hash, bits, txn_num, curr_tm=None, sig_flag=b'\x00', hi=0):
    if not gCard: return None  # failed
    
    if not curr_tm: curr_tm = int(time.time())
    
    try:
      sCmd = b'\x80\x23' + sig_flag + b'\x00'
      sBlockInfo = block_hash + struct.pack('<II',bits,txn_num)
      sData = struct.pack('<IB',curr_tm,len(sBlockInfo)) + sBlockInfo
      sCmd = sCmd + struct.pack('<B',len(sData)) + sData
      
      res, status = transmit(hexlify(sCmd).decode('latin-1'))
      if status == '9000':
        if len(res) > 64:  # ecc signature must large than 64 bytes
          self.succ_blocks.append([curr_tm,hi])
          if len(self.succ_blocks) > self.SUCC_BLOCKS_MAX:
            del self.succ_blocks[: -self.SUCC_BLOCKS_MAX]
          
          return bytes(bytearray(res)) + sig_flag
    except:
      traceback.print_exc()
    
    return None  # failed

class PseudoWallet(object):
  def __init__(self, pubKey, pubHash, vcn=0):
    self.pub_key  = util.key.compress_public_key(unhexlify(pubKey))
    self.pub_hash = unhexlify(pubHash)
    self._vcn = vcn
    self.coin_type = b'\x00'   # fixed to '00'
    
    self.pub_addr = util.key.publickey_to_address(self.pub_key,self._vcn,self.coin_type,version=b'\x00')
    self.pin_code = '000000'   # always reset to '000000'
  
  def address(self):
    return self.pub_addr
  
  def publicHash(self):
    return self.pub_hash
  
  def publicKey(self):
    return self.pub_key
  
  def sign(self, payload):
    h = hashlib.sha256(payload).digest()  # h must be 32 bytes
    h = hexlify(h).decode('latin-1')      # convert to utf-8
    
    pinLen = len(self.pin_code) // 2
    sCmd = ('802100%02x%02x' % (pinLen << 5,pinLen + 32)) + self.pin_code + h
    
    res, status = transmit(sCmd)  # maybe raise error here
    if status == '9000':
      return ''.join(chr(ch) for ch in res).encode('latin-1')
    else: raise RuntimeError('TEE sign transaction failed')

def _startMining():
  global gPseudoWallet, gPoetClient
  
  try:
    pubKey  = getPubKey()
    pubHash = getPubKeyHash()
  except:
    print('warning: start mining failed (invalid account)')
    return
  
  gPseudoWallet = PseudoWallet(pubKey,pubHash)
  
  gPoetClient = PoetClient([TeeMiner(unhexlify(pubHash))],link_no=0,coin=coins.Newborntoken,name='client1')
  gPoetClient.start()
  gPoetClient.set_peer(MINING_NODE_ADDR)
  print('mining task starting ...')

def autoStartCard():
  global gBehavior
  
  if sys.flags.interactive: return   # interactive mode for debugging, ignore mining
  
  if time.time() - gStartTime < 10:  # only auto start when inserting card within 10 seconds
    res, status = transmit('80010400 00')  # get user behavior
    if status == '9000':
      gBehavior = (res[0] << 8) | res[1]
      if (gBehavior & 0x04) == 0x04: # auto mining
        _startMining()

#=====================
import requests

from nbc import wallet
from nbc import protocol
from nbc import script

def ORD(ch):   # compatible to python3
  return ch if type(ch) == int else ord(ch)

def CHR(i):    # compatible to python3
  return bytes(bytearray((i,)))

def hash_str(s):  # s is bytes, return str type
  return hexlify(s).decode('latin-1')

def fine_print(value):
  s = '%.8f' % (value/100000000,)
  if s.find('.') >= 0:
    s = s.rstrip('0')
    if s[-1] == '.': s = s[:-1]
  return s

def special_int(s):
  if not s: return 0
  if s[-1] == '-':
    return int('-' + s[:-1])
  else: return int(s)

class WalletApp(object):
  SHEET_CACHE_SIZE = 16
  
  WEB_SERVER_ADDR = ''
  
  def __init__(self, wallet, vcn=0, coin=curr_coin):
    self._wallet = wallet
    self._vcn = vcn
    self._coin = coin
    
    self._sequence = 0
    self._wait_submit = []
  
  def get_reject_msg_(self, r):
    sErr = None
    if r.status_code == 400:
      msg_err = protocol.Message.parse(r.content,self._coin.magic)
      if msg_err.command == protocol.UdpReject.command:
        sErr = msg_err.message
        if type(sErr) != str:
          sErr = sErr.decode('latin-1')
    return sErr or 'Meet unknown error'
  
  def prepare_txn1_(self, pay_to, ext_in, scan_count, min_utxo, max_utxo, sort_flag, from_uocks):
    if not self.WEB_SERVER_ADDR: return None
    
    self._sequence = self._sequence + 1
    pay_from = [ protocol.format.PayFrom(0,self._wallet.address()) ]
    if ext_in:
      for item in ext_in:
        if isinstance(item,_list_types):
          pay_from.append(protocol.format.PayFrom(item[0],item[1]))
        else: pay_from.append(item)
    if from_uocks is None:
      from_uocks = [0 for item in pay_from]
    pay_to = [protocol.format.PayTo(int(v*100000000),a) for (a,v) in pay_to]
    return protocol.MakeSheet(self._vcn,self._sequence,pay_from,pay_to,scan_count,min_utxo,max_utxo,sort_flag,from_uocks)
  
  def prepare_txn2_(self, protocol_id, str_list, scan_count, min_utxo, max_utxo, sort_flag, from_uock):
    if not self.WEB_SERVER_ADDR: return None
    
    str_list2 = []
    ii = 0               # 0x00000010 PUSH <MSG> PUSH <locate> PUSH <utf8-message>
    for s in str_list:   # 0x00000010 PUSH <PROOF> PUSH <locate> PUSH <hash32>
      if type(s) != bytes:
        s = s.encode('utf-8')
      if len(s) > 75:    # msg length must < 76 (OP_PUSHDATA1)
        print('Error: item of RETURN list should be short than 75 bytes')
        return None
      ii += len(s) + 2   # 2 is OP_PUSH(1) + LEN(1)
      if ii > 84:        # RETURN(1) + B(1) + ID(4) + 84 = 90
        print('Error: RETURN list exceed max byte length')
        return None
      str_list2.append(s)
    
    self._sequence = self._sequence + 1
    pay_from = [ protocol.format.PayFrom(0,self._wallet.address()) ]
    
    ex_args = []; ex_format = ''
    for s in str_list2:
      ex_format += 'BB%is' % len(s)
      ex_args.extend([76,len(s),s])    # 0x4c=76 is OP_PUSHDATA1
    ex_msg = struct.pack('<BBI'+ex_format,106,4,protocol_id,*ex_args) # 0x6a=106 is OP_RETURN
    pay_to = [protocol.format.PayTo(0,ex_msg)]  # value=0 means using RETURN script 
    
    return protocol.MakeSheet(self._vcn,self._sequence,pay_from,pay_to,scan_count,min_utxo,max_utxo,sort_flag,[from_uock])
  
  def submit_txn_(self, msg, submit):
    headers = {'Content-Type': 'application/octet-stream'}
    r = requests.post(self.WEB_SERVER_ADDR + '/txn/sheets/sheet',data=msg.binary(self._coin.magic),headers=headers,timeout=30)
    
    if r.status_code == 200:
      msg2 = protocol.Message.parse(r.content,self._coin.magic)
      if msg2.command == protocol.OrgSheet.command:
        # assert(msg2.sequence == self._sequence)
        
        # step 1: check message is not imitation
        # wait to do: verify msg.signature ...
        
        # check pay_to balance
        coin_hash = self._wallet.publicHash() + self._wallet.coin_type
        d = {}
        for p in msg.pay_to:
          if p.value != 0 or p.address[0:1] != b'\x6a':  # not OP_RETURN
            d[util.base58.decode_check(p.address)[1:]] = p.value
        for idx in range(len(msg2.tx_out)):
          item = msg2.tx_out[idx]
          if item.value == 0 and item.pk_script[0:1] == b'\x6a':   # OP_RETURN
            continue  # ignore
          
          addr = script.get_script_address(item.pk_script,None)
          if not addr:
            print('Error: invalid output address (idx=%i)' % (idx,))
            return 0
          else:
            value_ = d.pop(addr,None)
            if item.value != value_:
              if (value_ is None) and addr[2:] == coin_hash:
                pass
              else:
                print('Error: invalid output value (idx=%i)' % (idx,))
                return 0
        
        for addr in d.keys():
          if coin_hash != addr[2:]:   # the left address should be pay-to-self
            print('Error: unknown output address (%s)' % (hexlify(addr),))
            return 0                  # be ensure not pay to unexpected person
        
        # step 2: sign first pks_out (numbers of tx_in)
        pks_out0 = msg2.pks_out[0].items; pks_num = len(pks_out0)
        tx_ins2 = []
        pub_key = self._wallet.publicKey()
        for (idx,tx_in) in enumerate(msg2.tx_in):   # sign every inputs
          if idx < pks_num:
            hash_type = 1
            payload = script.make_payload(pks_out0[idx],msg2.version,msg2.tx_in,msg2.tx_out,0,idx,hash_type)  # lock_time=0
            try:
              sig = self._wallet.sign(payload) + CHR(hash_type)  # maybe raise RuntimeError in _wallet.sign()
              sig_script = CHR(len(sig)) + sig + CHR(len(pub_key)) + pub_key
              tx_ins2.append(protocol.TxnIn(tx_in.prev_output,sig_script,tx_in.sequence))
            except RuntimeError as e:
              print('Error: ' + str(e))
              return 0
          else: tx_ins2.append(tx_in)
        
        # step 3: make payload and submit
        txn = protocol.Transaction(msg2.version,tx_ins2,msg2.tx_out,msg2.lock_time,b'') # sig_raw = b''
        payload = txn.binary(self._coin.magic)
        hash_ = util.sha256d(payload[24:-1])   # exclude sig_raw
        
        state_info = [msg2.sequence,txn,'requested',hash_,msg2.last_uocks]
        self._wait_submit.append(state_info)
        while len(self._wait_submit) > self.SHEET_CACHE_SIZE:
          del self._wait_submit[0]
        
        if submit:
          unsign_num = len(msg2.tx_in) - pks_num
          if unsign_num != 0:  # leaving to sign
            print('Warning: some input not signed: %i' % (unsign_num,))
            # return 0
          else:
            r2 = requests.post(self.WEB_SERVER_ADDR + '/txn/sheets/txn',data=txn.binary(self._coin.magic),headers=headers,timeout=30)
            if r2.status_code == 200:
              msg3 = protocol.Message.parse(r2.content,self._coin.magic)
              if msg3.command == protocol.UdpConfirm.command and msg3.hash == hash_:
                state_info[2] = 'submited'
                return msg2.sequence
              # else: return 0     # meet unexpected error
            else:
              print('Error: ' + self.get_reject_msg_(r2))
              # return 0
        else: return msg2.sequence
    
    else:
      print('Error: ' + self.get_reject_msg_(r))
    
    return 0
  
  def query_sheet(self, pay_to, ext_in=None, submit=True, scan_count=0, min_utxo=0, max_utxo=0, sort_flag=0, from_uocks=None):
    msg = self.prepare_txn1_(pay_to,ext_in,scan_count,min_utxo,max_utxo,sort_flag,from_uocks)
    if not msg: return 0
    return self.submit_txn_(msg,submit)
  
  def query_sheet_ex(self, protocol_id, str_list, submit=True, scan_count=0, min_utxo=0, max_utxo=0, sort_flag=0, from_uock=0):
    msg = self.prepare_txn2_(protocol_id,str_list,scan_count,min_utxo,max_utxo,sort_flag,from_uock)
    if not msg: return 0
    return self.submit_txn_(msg,submit)
  
  def submit_again(self, sn):
    for state_info in self._wait_submit:
      if state_info[0] == sn:
        txn, old_state, hash_ = state_info[1:4]
        
        headers = {'Content-Type': 'application/octet-stream'}
        r2 = requests.post(self.WEB_SERVER_ADDR + '/txn/sheets/txn',data=txn.binary(self._coin.magic),headers=headers,timeout=30)
        if r2.status_code == 200:
          msg3 = protocol.Message.parse(r2.content,self._coin.magic)
          if msg3.command == protocol.UdpConfirm.command and msg3.hash == hash_:
            state_info[2] = state = 'submited'
            return state
        else:
          print('Error: ' + self.get_reject_msg_(r2))
        break
    
    return 'unknown'
  
  def submit_info(self, sn):
    for (sn2,txn,state,hash2,uocks) in self._wait_submit:
      if sn2 == sn:
        return (txn,state,hash2,uocks)
    return (None,'unknown',None,None)
  
  def submit_state(self, sn):
    for (sn2,txn,state,hash2,uocks) in self._wait_submit:
      if sn2 == sn:
        return state
    return 'unknown'
  
  def confirm_state(self, hash_):  # try update confirm state
    if type(hash_) != bytes:
      hash_ = hash_.encode('latin-1')
    hash2 = hexlify(hash_).decode('latin-1')
    
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    r = requests.get(self.WEB_SERVER_ADDR + '/txn/sheets/state',params={'hash':hash2},headers=headers,timeout=30)
    if r.status_code == 200:
      msg3 = protocol.Message.parse(r.content,self._coin.magic)
      if msg3.command == protocol.UdpConfirm.command and msg3.hash == hash_:
        hi  = msg3.arg & 0xffffffff
        num = (msg3.arg >> 32) & 0xffff
        idx = (msg3.arg >> 48) & 0xffff
        state = 'confirm=%i, height=%i, index=%i' % (num,hi,idx)
        return state
    else:
      sErr = self.get_reject_msg_(r)
      if sErr == 'in pending state':
        return 'pending'           # peer has received it but still in waiting publish
      else: print('Error: ' + sErr)
    return 'unknown'
  
  def confirm_state_sn(self, sn):  # try update confirm state
    for state_info in self._wait_submit:
      if state_info[0] != sn: continue
      
      state_ = state_info[2]  # state_info: (sn2,txn,state_,hash_,uocks)
      if state_ == 'submited' or state_[:8] == 'confirm=':
        state = self.confirm_state(state_info[3])
        if state[:8] == 'confirm=':
          state_info[2] = state
        return state
      break
    
    return 'unknown'
  
  def account_state(self, uock_from=0, uock_before=0, another=None): # try query all UTXO if there is not much
    # get account:bytes and account2:str
    account = another if another else self._wallet.address()
    if type(account) == bytes:
      account2 = account.decode('latin-1')
    else:  # account should be str type
      account2 = account
      account = account.encode('latin-1')
    
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    r = requests.get(self.WEB_SERVER_ADDR + '/txn/state/account',params={'addr':account2,'uock':uock_from,'uock2':uock_before},headers=headers,timeout=30)
    if r.status_code == 200:
      msg = protocol.Message.parse(r.content,self._coin.magic)
      if msg.command == protocol.AccState.command:
        if msg.account == account:  # msg.link_no is peer's node._link_no
          total = sum(u.value for u in msg.found)
          sDesc = 'Total unspent: %s' % (fine_print(total),)
          if len(msg.found) == msg.search:    # meet limit, should have more UTXO
            sDesc += ' (not search all yet)'
          
          print('Public address: %s' % (account2,))
          print(sDesc)
          print('List of (uock,height,value):' + ('' if msg.found else ' none'))
          for u in msg.found:
            print('  %14s, %10s, %14s' % (u.uock,u.height,fine_print(u.value)))
          print('')
    else:
      print('Error: ' + self.get_reject_msg_(r))
  
  def block_state(self, block_hash, heights=None):  # block_hash should be str or None
    if block_hash:
      if type(block_hash) != bytes:
        block_hash = block_hash.encode('latin-1')
      hash2 = hexlify(block_hash).decode('latin-1')
    else: hash2 = '00' * 32
    
    if heights:
      heights = [special_int(hi) for hi in heights]
    else: heights = []
    
    if not block_hash and not heights:
      print('warning: nothing to query.')
      return
    
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    account = self._wallet.address()
    if type(account) == bytes:
      account2 = account.decode('latin-1')
    else: account2 = account  # account2 should be str type
    
    r = requests.get(self.WEB_SERVER_ADDR + '/txn/state/block',params={'hash':hash2,'hi':heights},headers=headers,timeout=30)
    if r.status_code == 200:
      msg = protocol.Message.parse(r.content,self._coin.magic)
      if msg.command == protocol.ReplyHeaders.command:
        if not msg.headers:
          print('no block is found!')
        else:
          for (idx,block) in enumerate(msg.headers):
            hi = msg.heights[idx]
            txck = msg.txcks[idx]
            
            print('Block(height=%i,txck=%i):' % (hi,txck))
            print('  hash: %s' % (hash_str(block.hash),))
            print('  version: %i' % (block.version,))
            print('  link_no: 0x%x' % (block.link_no,))
            print('  prev_block:  %s' % (hash_str(block.prev_block),))
            print('  merkle_root: %s' % (hash_str(block.merkle_root),))
            print('  timestamp: %i' % (block.timestamp,))
            print('  bits:  %i' % (block.bits,))
            print('  nonce: %i' % (block.nonce,))
            print('  miner: %s' % (hash_str(block.miner),))
            print('  txn_count: %i' % (block.txn_count,))
            print('')
    else:
      print('Error: ' + self.get_reject_msg_(r))
  
  def utxo_state(self, uocks=5, address=None):  # query txns in list or num of txns
    if type(uocks) == int:
      num = uocks
      uocks = []
    else:
      num = 0
      uocks = list(uocks)     # [uock1,uock2, ...]
    
    if not address:
      account = self._wallet.address()
    else: account = address
    if type(account) == bytes:
      account2 = account.decode('latin-1')
    else: account2 = account  # account2 should be str type
    
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    r = requests.get(self.WEB_SERVER_ADDR + '/txn/state/uock',params={'addr':account2,'num':num,'uock':uocks},headers=headers,timeout=30)
    if r.status_code == 200:
      msg = protocol.Message.parse(r.content,self._coin.magic)
      if msg.command == protocol.UtxoState.command:
        for (idx,txn) in enumerate(msg.txns):
          hi = msg.heights[idx]
          flag = msg.indexes[idx]   # flag: higher 16 bits is txns[index], lower 16 bits is out[index]
          curr_idx = flag & 0xffff
          
          print('Block(height=%i)[%i]:' % (hi,(flag >> 16) & 0xffff))
          print('  lock: 0x%x' % (txn.lock_time,))
          
          for (idx2,item2) in enumerate(txn.tx_in):
            print('  in[%i].prev.hash:\n    %s' % (idx2,hash_str(item2.prev_output.hash)))
            print('  in[%i].prev.index: %i' % (idx2,item2.prev_output.index))
          for (idx2,item2) in enumerate(txn.tx_out):
            ss = '*' if curr_idx == idx2 else ''
            print('  %sout[%i].value: %s' % (ss,idx2,fine_print(item2.value)))
            tok = script.Tokenizer(item2.pk_script)
            print('  %sout[%i].script: (oid=%x)\n    %s' % (ss,idx2,(hi<<32)|flag,tok))
          print('')
    else:
      print('Error: ' + self.get_reject_msg_(r))

#=====================
import re, random

_BASE58_CHAR = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
_TX_TRANSFER_MAX = 1000000000000     # 10000 NBC

_BREAK_LOOP = '\npress Ctrl+C to break query loop, transaction starting ...\n'

def checkPseudoWallet():
  global gPseudoWallet
  if gPseudoWallet:
    return gPseudoWallet
  
  pubKey = getPubKey()
  pubHash = getPubKeyHash()
  if pubKey and pubHash:
    gPseudoWallet = PseudoWallet(pubKey,pubHash)
    return gPseudoWallet
  else: return None

def randomData(size):
  b = [random.randint(0,255) for i in range(size)]
  return ''.join('%02x' % ch for ch in b)

def printCmdHelp():
  print( '''All commands:
  help      : print help
  break     : break command loop

  info [before=uock] [after=uock]
            : account information
  block [hash=block_id] [height]+
            : query block, "1-" for last one 
  utxo [num=5] [uock=id]
            : max list "num" of utxo or only list "uock" item
  transfer [after=uock] [hash=tx_id] [addr=nbc]+
            : transfer NBC to other account
  record [proof=1] [where=location] [after=uock] [hash=tx_id] ["desc"]+
            : record message or finger print of proof

  start     : start mining
  stop      : stop mining

  account   : show current NBC account
  create    : generate NBC account in TEE, only one time
  import    : import NBC account to TEE, only one time

  getpass   : verify PIN
  setpass   : change PIN
  bind      : bind phone number to TEE
  config [level=1|2|3] [automining=0|1]
            : change security level or auto mining
  export    : export NBC account to private_sn.bak file
  restore   : restore NBC account from private_sn.bak\n''' )

def cmdLoop():
  printCmdHelp()
  print('type "break" to quit command loop ...\n')
  
  conn = None; sCmd = ''
  while True:
    sCmd = input('\ncmd>').strip()
    if sCmd == 'break':
      break
    
    if not gCard:  # detect card exist or not
      if sCmd == 'help':
        printCmdHelp()
      else: print('! warning: no smart card, command (%s) is ignored' % (sCmd,))
      continue
    
    conn = gCard.connection
    try:
      if sCmd == 'account':
        pubAddr = getPubAddr(conn)
        pubKey = getPubKey(conn)
        pubHash = getPubKeyHash(conn)
        
        if pubAddr and pubKey and pubHash:
          print('public address:', pubAddr)
          print()
          print('public key:', pubKey)
          print('public keyhash:', pubHash)
        else:
          print('no account found.')
      
      elif sCmd[:4] == 'info':
        if not checkPseudoWallet():
          print('TEE wallet not ready yet!')
          continue
        
        b = sCmd[4:].split()
        
        uockBefore = 0; uockAfter = 0
        for item in b:
          bTmp = item.split('=')
          if bTmp[0] == 'before':
            uockBefore = int(bTmp[1])
          elif bTmp[0] == 'after':
            uockAfter = int(bTmp[1])
        
        sAddr = gPseudoWallet.address()
        if type(sAddr) == bytes:
          sAddr = sAddr.decode('latin-1')
        # print('Public address: %s' % (sAddr,))  # should print in app.account_state()
        
        app = WalletApp(gPseudoWallet,vcn=0)
        app.WEB_SERVER_ADDR = curr_coin.WEB_SERVER_ADDR
        app.account_state(uockAfter,uockBefore)
      
      elif sCmd[:6] == 'block ':
        if not checkPseudoWallet():
          print('TEE wallet not ready yet!')
          continue
        
        b = sCmd[6:].split()
        
        block_hash = None
        heights = []
        for item in b:
          bTmp = item.split('=')
          if len(bTmp) == 2:
            if bTmp[0] == 'hash':
              block_hash = unhexlify(bTmp[1])
          else: heights.append(item)
        
        app = WalletApp(gPseudoWallet,vcn=0)
        app.WEB_SERVER_ADDR = curr_coin.WEB_SERVER_ADDR
        app.block_state(block_hash,heights)
      
      elif sCmd[:4] == 'utxo':
        if not checkPseudoWallet():
          print('TEE wallet not ready yet!')
          continue
        
        b = sCmd[4:].split()
        
        uocks = 5
        for item in b:
          bTmp = item.split('=')
          if bTmp[0] == 'uock':
            uocks = [int(bTmp[1])]  
          elif bTmp[0] == 'num':
            uocks = int(bTmp[1])
        
        app = WalletApp(gPseudoWallet,vcn=0)
        app.WEB_SERVER_ADDR = curr_coin.WEB_SERVER_ADDR
        app.utxo_state(uocks)
      
      elif sCmd[:9] == 'transfer ':
        if not checkPseudoWallet():
          print('TEE wallet not ready yet!')
          continue
        
        b = sCmd[9:].split()
        
        after = 0; hash_ = None
        pay_to = []
        for item in b:
          succ = False
          bTmp = item.split('=')
          if len(bTmp) == 2:
            targ_addr, f = bTmp[0], bTmp[1]
            if targ_addr == 'after':
              after = int(f)
              continue
            elif targ_addr == 'hash':
              hash_ = f
              continue
            
            try:
              if len(targ_addr) > 32:  # base58 addr must large than 32 bytes
                for ch in targ_addr:
                  if ch not in _BASE58_CHAR:
                    raise Exception('invalid address')
                f = float(f)
                if 0 < f <= _TX_TRANSFER_MAX:
                  pay_to.append((targ_addr,f))
                  succ = True
            except: pass
          
          if not succ:
            raise Exception('Invalid target: %s' % (item,))
        
        app = WalletApp(gPseudoWallet,vcn=0)
        app.WEB_SERVER_ADDR = curr_coin.WEB_SERVER_ADDR
        
        state = ''
        txn_hash = None
        if hash_:
          txn_hash = unhexlify(hash_)
        else:
          if not pay_to:
            print('warning: pay to nobody')
            continue
          
          psw = inputPin()
          if not psw: continue
          gPseudoWallet.pin_code = psw
          psw = ''
          
          try:
            sn = app.query_sheet(pay_to,from_uocks=[after])
            if sn:
              info = app.submit_info(sn)
              state = info[1]; txn_hash = info[2]; last_uocks = info[3]
              if state == 'submited' and txn_hash:
                sDesc = '\nTransaction state: %s' % (state,)
                if last_uocks: sDesc += ', last uock: %s' % (last_uocks[0],)
                print(sDesc)
                print('Transaction hash: %s' % (hexlify(txn_hash).decode('latin-1'),))
          finally:
            gPseudoWallet.pin_code = '000000'
        
        if txn_hash:
          print(_BREAK_LOOP)
          while True:
            try:
              time.sleep(90 if state[:8] == 'confirm=' else 15)
              state = app.confirm_state(txn_hash)
              print('Transaction state: %s' % (state,))
            except KeyboardInterrupt:
              print('')
              break
            except:
              traceback.print_exc()
      
      elif sCmd[:7] == 'record ':
        if not checkPseudoWallet():
          print('TEE wallet not ready yet!')
          continue
        
        sLine = ''
        iPos = sCmd.find('"')
        if iPos > 0:
          sLine = sCmd[iPos:]
          sCmd = sCmd[:iPos].strip()
        
        b = sCmd[7:].split()
        where = '0'; proof = 0; after=0
        hash_ = None
        for item in b:
          bTmp = item.split('=')
          if len(bTmp) == 2:
            if bTmp[0] == 'where':
              where = bTmp[1]
            elif bTmp[0] == 'proof':
              proof = int(bTmp[1])
            elif bTmp[0] == 'after':
              after = int(bTmp[1])
            elif bTmp[0] == 'hash':
              hash_ = bTmp[1]
        
        app = WalletApp(gPseudoWallet,vcn=0)
        app.WEB_SERVER_ADDR = curr_coin.WEB_SERVER_ADDR
        
        state = ''
        txn_hash = None
        if hash_:
          txn_hash = unhexlify(hash_)
        else:
          content = re.findall(r'"[^"]*"',sLine)
          content = [ss[1:-1] for ss in content]
          if not content:
            print('warning: nothing to record')
            return
          content = '\n'.join(content)
          
          psw = inputPin()
          if not psw: continue
          gPseudoWallet.pin_code = psw
          psw = ''
          
          try:
            if proof:
              sn = app.query_sheet_ex(0,['PROOF',where,content],from_uock=after)
            else: sn = app.query_sheet_ex(0,['MSG',where,content],from_uock=after)
            if sn:
              info = app.submit_info(sn)
              state = info[1]; txn_hash = info[2]; last_uocks = info[3]
              if state == 'submited' and txn_hash:
                sDesc = '\nTransaction state: %s' % (state,)
                if last_uocks: sDesc += ', last uock: %s' % (last_uocks[0],)
                print(sDesc)
                print('Transaction hash: %s' % (hexlify(txn_hash).decode('latin-1'),))
          finally:
            gPseudoWallet.pin_code = '000000'
        
        if txn_hash:
          print(_BREAK_LOOP)
          while True:
            try:
              time.sleep(90 if state[:8] == 'confirm=' else 15)
              state = app.confirm_state(txn_hash)
              print('Transaction state: %s' % (state,))
            except KeyboardInterrupt:
              print('')
              break
            except:
              traceback.print_exc()
      
      elif sCmd == 'start':
        if gPoetClient and gPoetClient.is_alive():
          print('TEE already in mining.')
        else: _startMining()
      
      elif sCmd == 'stop':
        if gPoetClient and gPoetClient.is_alive():
          gPoetClient.exit()
        else: print('TEE is not in mining.')
      
      elif sCmd == 'create':
        if getPubKeyHash(conn):
          print('invalid state: account already exists in TEE')
          continue
        
        print('warning: create account only once in TEE, there is no way to UNDO the operation.\n')
        if input('do you want continue? Yes or No, (Y/N): ') not in ('Y','y'):
          continue
        
        psw = inputPin()
        if not psw: continue
        
        inCmd = ('802000%02x%02x' % (len(psw) // 2,len(psw) // 2)) + psw
        psw = ''   # avoid leak out
        
        try:
          res, status = transmit(inCmd,conn)
          if status == '9000':
            if len(res) == 65:
              print('generate account successful!')
              print('public key:',''.join(('%02x' % ch) for ch in res))
              continue
          print('generate account failed!')
        except:
          if gLastErrCode[:3] == '63c':     # 63cX, authorization failed
            print('error: incorrect PIN code, left try count is ' + gLastErrCode[-1:]) # max try count is 5
          elif gLastErrCode == '6985':      # SW_CONDITIONS_NOT_SATISFIED, account is ready 
            print('error: account already exists.')
          elif gLastErrCode == '6700':
            print('error: invalid length.') # SW_WRONG_LENGTH
          else:
            print('generate account failed: unknown reason.')
        inCmd = ''   # avoid leak out
      
      elif sCmd == 'import':
        if getPubKeyHash(conn):
          print('invalid state: account already exists in TEE')
          continue
        
        print('warning: create account only once in TEE, there is no way to UNDO the operation.\n')
        if input('do you want continue? Yes or No, (Y/N): ') not in ('Y','y'):
          continue
        
        psw = inputPin()
        if not psw: continue
        
        sKey = getpass.getpass('input private key: ')
        sKey = ''.join(sKey.split())
        if len(sKey) != 64:
          print('error: private key should be 32 bytes')
          continue
        elif not re.match(r'^[0-9a-fA-F]+$',sKey):
          print('error: invalid private key')
          continue
        
        inCmd = psw + sKey
        inCmd = ('802001%02x%02x' % (len(psw) // 2,len(inCmd) // 2)) + inCmd
        psw = ''; sKey = ''   # avoid leak out
        
        try:
          res, status = transmit(inCmd,conn)
          if status == '9000':
            if len(res) == 65:
              print('import account successful!')
              print('public key:',''.join(('%02x' % ch) for ch in res))
              continue
          print('import account failed!')
        except:
          if gLastErrCode[:3] == '63c':     # 63cX, authorization failed
            print('incorrect PIN code, left try count: ' + gLastErrCode[-1:]) # max try count is 5
          elif gLastErrCode == '6985':      # SW_CONDITIONS_NOT_SATISFIED, account is ready 
            print('error: account already exists.')
          elif gLastErrCode == '6700':
            print('error: invalid length.') # SW_WRONG_LENGTH
          else:
            print('import account failed: unknown reason.')
        inCmd = ''   # avoid leak out
      
      elif sCmd == 'getpass':
        psw = inputPin()
        if not psw: continue
        
        try:
          res, status = transmit(('00200000%02x' % (len(psw)//2,)) + psw)
          print('verify PIN code successful.')
        except:
          if gLastErrCode[:3] == '63c':     # 63cX, authorization failed
            print('incorrect PIN code, left try count: ' + gLastErrCode[-1:]) # max try count is 5
          else: print('verify PIN code failed.')
      
      elif sCmd == 'setpass':
        psw = inputPin()
        if not psw: continue
        
        newPin = getpass.getpass('input new PIN: ')
        if newPin != getpass.getpass('type new PIN again: '):
          print('warning: second input mismatch to the previous one')
          continue
        
        if not re.match(r'^\d+$',newPin):
          print("invalid PIN (expected '0'-'9' number)")
          continue
        if len(newPin) < 3 or len(newPin) > 10:
          print('invalid PIN length')
          continue
        if (len(newPin) & 0x01) == 0x01: newPin += 'f'
        
        inCmd = psw + 'ff' + newPin
        inCmd = ('002e0000%02x' % (len(inCmd)//2,)) + inCmd
        psw = ''
        
        try:
          res, status = transmit(inCmd,conn)
          if status == '9000':
            print('change PIN successful.')
        except:
          if gLastErrCode[:3] == '63c':     # 63cX, authorization failed
            print('incorrect PIN code, left try count: ' + gLastErrCode[-1:]) # max try count is 5
          else: print('change PIN code failed')
        inCmd = ''
      
      elif sCmd == 'bind':
        print('warning: every TEE only can be bound once, there is no way to UNDO the operation.\n')
        if input('do you want continue? Yes or No, (Y/N): ') not in ('Y','y'):
          continue
        
        psw = inputPin()
        if not psw: continue
        
        sPhone = input('input phone number: ').strip()
        if not re.match(r'^\d+$',sPhone) or len(sPhone) <= 10 or len(sPhone) >= 13:
          print('error: incorrect phone number')
          continue
        
        inCmd = psw + ''.join('3'+ch for ch in sPhone)  # '0' --> '30', '9' --> '39'
        inCmd = ('802600%02x%02x' % (len(psw)//2,len(inCmd)//2)) + inCmd
        psw = ''
        
        try:
          res, status = transmit(inCmd,conn)
          if status == '9000':
            print('bind phone number successful.')
        except:
          if gLastErrCode[:3] == '63c':     # 63cX, authorization failed
            print('incorrect PIN code, left try count: ' + gLastErrCode[-1:]) # max try count is 5
          elif gLastErrCode == '6985':
            print('can not bind phone number to TEE at second time')
          else: print('bind phone number failed, error code:',gLastErrCode)
        inCmd = ''   # avoid leak out
      
      elif sCmd[:7] == 'config ':
        # [level=1|2|3] [automining=0|1]
        b = sCmd[7:].split()
        
        newLevel = None; newAuto = None
        for item in b:
          bTmp = item.split('=')
          if len(bTmp) == 2:
            if bTmp[0] == 'level':
              newLevel = int(bTmp[1])
              if newLevel != 1 and newLevel != 2 and newLevel != 3:
                raise Exception('invalid argument: level=' + bTmp[1])
            elif bTmp[0] == 'automining':
              newAuto = int(bTmp[1])
              if newAuto != 0 and newAuto != 1:
                raise Exception('invalid argument: automining=' + bTmp[1])
        
        psw = inputPin()
        if not psw: continue
        
        succ = True; succAny = False
        if newLevel is not None:
          inCmd = psw + ('%02x' % (newLevel,))
          inCmd = ('802400%02x%02x' % (len(psw)//2,len(inCmd)//2)) + inCmd
          
          try:
            res, status = transmit(inCmd,conn)
            if status == '9000':
              succAny = True
            else: succ = False
          except:
            succ = False
            if gLastErrCode[:3] == '63c':     # 63cX, authorization failed
              print('incorrect PIN code, left try count: ' + gLastErrCode[-1:]) # max try count is 5
            else: print('config failed: level=%s' % (newLevel,))
        
        if succ and (newAuto is not None):
          inCmd = psw + ('%02x' % (newAuto,))
          inCmd = ('802401%02x%02x' % (len(psw)//2,len(inCmd)//2)) + inCmd
          
          try:
            res, status = transmit(inCmd,conn)
            if status == '9000':
              succAny = True
            else: succ = False
          except:
            succ = False
            if gLastErrCode[:3] == '63c':     # 63cX, authorization failed
              print('incorrect PIN code, left try count: ' + gLastErrCode[-1:]) # max try count is 5
            else: print('config failed: automining=%s' % (newAuto,))
        
        if succAny:
          if succ:
            print('save config successful.')
          else: print('save config finished.')
      
      elif sCmd == 'export':
        sn = getSerialNo(conn)
        sFile = 'private_' + sn + '.bak'
        if os.path.exists(os.path.join('.',sFile)):
          print('file (%s) already exist in local directory, please delete it first.' % (sFile,))
          continue
        
        psw = inputPin()
        if not psw: continue
        
        inCmd = psw + ('%02x%02x%02x%02x' % (ord('p'),ord('r'),ord('i'),ord('v')))
        inCmd = ('802900%02x%02x' % (len(psw)//2,len(inCmd)//2)) + inCmd
        psw = ''
        
        try:
          res, status = transmit(inCmd,conn)
          if status == '9000':
            with open(os.path.join('.',sFile),'wb') as f:
              f.write(bytes(bytearray(res)))
            print('export private key to file (%s) successful.' % (sFile,))
        except:
          if gLastErrCode[:3] == '63c':     # 63cX, authorization failed
            print('incorrect PIN code, left try count: ' + gLastErrCode[-1:]) # max try count is 5
          elif gLastErrCode == '6a80' or gLastErrCode == '6a88':
            print('invalid account')
          else: print('export private key failed, error code:',gLastErrCode)
        inCmd = ''   # avoid leak out
      
      elif sCmd == 'restore':
        sn = getSerialNo(conn)
        sFile = 'private_' + sn + '.bak'
        if not os.path.isfile(os.path.join('.',sFile)):
          print('can not find file (%s) in local directory.' % (sFile,))
          continue
        
        inCmd = open(os.path.join('.',sFile),'rb').read()
        inCmd = [int(ch) for ch in inCmd]
        if len(inCmd) != 256:
          print('incorrect file length:',sFile)
          continue
        
        psw = inputPin()
        if not psw: continue
        
        # step 1: verify PIN
        try:
          transmit(('00200000%02x' % (len(psw)//2,)) + psw,conn)
          psw = ''
        except:
          psw = ''
          if gLastErrCode[:3] == '63c':
            print('incorrect PIN code, left try count: ' + gLastErrCode[-1:]) # max try count is 5
          continue
        
        # step 2: run restore
        try:
          transmit([0x80,0x30,0x00,0x01,0x80] + inCmd[:0x80],conn)  # send first 128 bytes
          res, status = transmit([0x80,0x30,0x00,0x04,0x80] + inCmd[0x80:],conn)  # send last 128 bytes
          if status == '9000':
            print('restore account successful!')
            print('public key:',''.join(('%02x' % ch) for ch in res))
        except:
          if gLastErrCode == '6982':
            print('security check failed')
          elif gLastErrCode == '6a88':
            print('invalid account')
          elif gLastErrCode == '6a80':
            print('invalid data format')
          else: print('restore private key failed, error code:',gLastErrCode)
      
      elif sCmd:     # unknown command
        printCmdHelp()
    
    except Exception as e:
      if sys.flags.interactive:  # start with 'python -i' means work at debug mode
        traceback.print_exc()
      else: print('! meet error: ' + str(e))
  
  if gPoetClient and not sys.flags.interactive:
    gPoetClient.exit()
  print('... exit command loop.\n')


if __name__ == '__main__':
  time.sleep(1)
  print()
  
  cmdLoop()
  monitor.deleteObserver(observer)

# usage: python [-i] wallet.py [--verbose] [--pool pool.domain.com:port]
#   -i            interactive mode
#   --verbose     print APDU commands and responses
