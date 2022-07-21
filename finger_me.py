import pygatt
import hashlib
from pyfingerbot import XRequest, Coder, TuyaDataPacket, BleReceiver, SecretKeyManager, FingerBot
import time
from struct import unpack
from Crypto.Cipher import AES
from binascii import unhexlify, hexlify

# Use https://github.com/redphx/tuya-local-key-extractor to get these values
LOCAL_KEY = ''
MAC = ''
UUID = ''
DEV_ID = ''

fingerbot = FingerBot(MAC, LOCAL_KEY, UUID, DEV_ID)
fingerbot.connect()