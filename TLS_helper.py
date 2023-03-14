import base64
import hmac
from hashlib import sha256

import ECDH


# Hello contains:
# version, session ID, cipher_suite, compress_methods, random,
class Hello:
    def __init__(self):
        self.version = ""
        self.random = ""
        self.session_id = ""  # 32B not necessarily random but unpredictable
        self.cipher_suites = ""
        self.compression_methods = ""


class Local:
    def __init__(self):
        self.hello = Hello()
        self.keyexPara = ECDH.ECDHPara()
        self.server_random = 0
        self.client_random = 0
        self.session_key = 0
        self.isReq = 0
        self.ispeer_cert_ok = 0
        self.cwrK = 0  # client_write_key
        self.swrK = 0   # server_write_key
        self.cMacK = 0  # client_write_MAC_key
        self.sMacK = 0  # server_write_MAC_key


def gene_sessionkey(local):
    print("\n[generate Session Key]")
    s_Rand = local.server_random.to_bytes(32, "little")
    c_Rand = local.client_random.to_bytes(32, "little")
    # sharedkey in ECDH serves as pre_master_secret
    pms = local.keyexPara.sharedKey
    pms = int(pms.split("0x")[1], 16).to_bytes(33, "little")
    pre_master_secret = pms
    # generate sessionkey
    SessionKey = base64.b64encode(
        hmac.new(pre_master_secret, s_Rand + c_Rand, digestmod=sha256).digest())
    print("SessionKey:" + str(SessionKey))
    client_write_key = SessionKey[:8]
    server_write_key = SessionKey[8:16]
    client_write_MAC_key = SessionKey[16:30]
    server_write_MAC_key = SessionKey[30:]
    print("client_write_key:" + str(client_write_key))
    print("server_write_key:" + str(server_write_key))
    print("client_write_MAC_key: " + str(client_write_MAC_key))
    print("server_write_MAC_key: " + str(server_write_MAC_key))

    local.cwrK = client_write_key
    local.swrK = server_write_key
    local.cMacK = client_write_MAC_key
    local.sMacK = server_write_MAC_key

    return local
