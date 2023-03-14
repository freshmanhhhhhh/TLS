from tinyec import registry
import secrets

curve = registry.get_curve('brainpoolP256r1')


class ECDHPara:
    def __init__(self):
        self.curve = curve
        self.priKey = 0  # 256 bit
        self.pubKey = 0
        self.peer_pkey_x = 0
        self.peer_pkey_y = 0
        self.sharedKey = 0


# compressed EC point for 256-bit curve, encoded as 65 hex digits(33B)
def compress(pubKey):
    return hex(pubKey.x) + hex(pubKey.y % 2)[2:]


def genekey(para):
    para.priKey = secrets.randbelow(para.curve.field.n)
    para.pubKey = para.priKey * para.curve.g
    return para


def set_shared_key(para):
    para.sharedKey = compress(para.peer_pkey * para.priKey)
    return para
