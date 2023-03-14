import base64
from hashlib import sha256

from socket import *
import os
import secrets
import time
import subprocess
import tinyec.ec as ec
import hmac

from Crypto.Cipher import DES

import TLS_helper
import ECDH

# help to read field from client_hello
Version = 0
Random = 1
Sid = 2
CipherS = 3
ComM = 4

# create socket
serverName = '127.0.0.1'  # 指定服务器IP地址
serverPort = 1234
clientSocket = socket(AF_INET, SOCK_STREAM)  # 建立TCP套接字，使用IPv4协议
clientSocket.connect((serverName, serverPort))  # 向服务器发起连接

s_random = 0


def client_hello():
    print("\n------Handshake Protocol: Client Hello------")
    print("\n[CLIENT HELLO]")
    # 加密套件列表，仅实现如下一个加密套件
    # CipherSuites = ["TLS_ECDHE_RSA_WITH_DES_SHA256"]
    clt_hello = TLS_helper.Hello()
    clt_hello.version = "TLS 1.2"  # 0x0303
    clt_hello.random = secrets.randbits(256) # 32字节
    clientSocket.send(clt_hello.random.to_bytes(32, 'little'))
    time.sleep(0.1)
    clt_hello.session_id = secrets.token_bytes(32)
    # FORMAT: TLS_密钥交换算法_身份认证算法_WITH_对称加密算法_消息摘要算法
    # 仅支持一个加密套件
    clt_hello.cipher_suites = "TLS_ECDHE_RSA_WITH_DES_SHA256"
    clt_hello.compression_methods = "null"
    # print
    display = "Version: " + clt_hello.version + "\n"
    display += "Random: " + str(clt_hello.random) + "\n"
    display += "Session ID: " + str(clt_hello.session_id) + "\n"
    display += "Cipher Suite: " + str(clt_hello.cipher_suites) + "\n"
    display += "Compression Methods: " + clt_hello.compression_methods + "\n"
    print(display)
    clientSocket.send(display.encode())
    return clt_hello


def after_serverHelloDone(clt_local):
    print("-----Handshake Protocol: Receive Server Hello-----")

    # RECEIVED SERVER HELLO
    # 协商加密套件，保存服务器随机数随机数
    print("\n[RECEIVED SERVER HELLO]")
    clt_local.server_random = clientSocket.recv(1024)
    clt_local.server_random = int.from_bytes(clt_local.server_random, 'little')

    helloList = clientSocket.recv(1024).decode().split('\n')
    # 打印出服务器随机数和协商好的加密套件
    for i in helloList:
        if "Random" in i:
            print("Server " + i)
        if "Cipher" in i:
            print("Negotiated " + i)

    # RECV SERVER CERTIFICATE
    # verify server certificate
    print("\n[RECEIVED SERVER CERTIFICATE]")
    s_cert = clientSocket.recv(5000).decode()
    s_fp = "server.crt"
    # if this file exists, delete it
    current_path = os.getcwd()
    path = current_path + s_fp
    if os.path.exists(path):
        os.remove(path)
    # create and write server.crt
    f = open(s_fp, "a")
    f.write(s_cert)
    f.close()
    # verify server.crt in command line
    cmd = "openssl verify -CAfile s_ca.crt server.crt"
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    process.wait()
    cmd_output = process.stdout.read().decode('utf-8')
    print("input command : openssl verify -CAfile s_ca.crt server.crt")
    print("output: " + cmd_output)
    if "server.crt: OK" in cmd_output:
        clt_local.ispeer_cert_ok = 1
    else:
        print("invalid server certificate, end the connection! ")
        clientSocket.close()

    # recv server pubkey(ECDH)
    print('[RECEIVE SERVER ECDH PUBKEY]')
    ecdhpara = ECDH.ECDHPara()
    # ecdhpara.curve = clientSocket.recv(2048)
    ecdhpara = ECDH.genekey(ecdhpara)
    # receive (x,y) of server_pubkey
    ecdhpara.peer_key_x = clientSocket.recv(1024).decode()
    time.sleep(0.5)
    ecdhpara.peer_key_y = clientSocket.recv(1024).decode()
    # generate Point() type ECDH server_pubkey from its (x,y)
    x = int(ecdhpara.peer_key_x.split('0x')[1], 16)
    y = int(ecdhpara.peer_key_y.split('0x')[1], 16)
    ecdhpara.peer_pkey = ec.Point(ecdhpara.curve, x, y)
    print("server pubkey: " + ECDH.compress(ecdhpara.peer_pkey))
    ecdhpara = ECDH.set_shared_key(ecdhpara)
    clt_local.keyexPara = ecdhpara

    # 收到证书请求
    # 判断是否发送证书
    print('\n[RECEIVE SERVER CERTIFICATE REQUEST]')
    clt_local.isReq = clientSocket.recv(1024).decode()  # .replace("\n", "").split("Certificate Request: ")[1]
    print(clt_local.isReq)

    # 收到server hellodone
    print('[RECEIVE SERVER HELLO DONE]')
    s_hellodone = clientSocket.recv(1024).decode()
    print(s_hellodone)

    return clt_local


def client_certificate():
    print("-----Handshake Protocol: Client Certificate-----\n")
    cert_fp = "clientKey/client.crt"
    c_cert = open(cert_fp).read()
    clientSocket.send(c_cert.encode())
    print("send client certificate over\n")


def client_key_exchange(client_local):
    print("-----Handshake Protocol: Client Key Exchange(ECDH)-----\n")
    c_ECDHpara = client_local.keyexPara
    pkey = c_ECDHpara.pubKey
    # 发送客户端公钥的x,y坐标
    clientSocket.send(hex(pkey.x).encode())
    time.sleep(0.5)
    clientSocket.send(hex(pkey.y).encode())
    time.sleep(0.5)
    print("compressed client pkey: " + ECDH.compress(pkey) + '\n')
    print("[KEY EXCHANGE OVER]")
    print("shared key: " + str(c_ECDHpara.sharedKey))
    return c_ECDHpara


def pad(text):
    while len(text) % 8 != 0:
        text += ' '
    return text


def send_message(local):
    print("\n------Test: Send MSG------")
    print("\nplease input msg sent to server: ")

    # using hmac in digestmod=sha256 to compute MAC for msg
    msg = input()
    print("\n[ATTACH MAC & ENCRYPT]")
    mac = base64.b64encode(hmac.new(local.cMacK, msg.encode(), digestmod=sha256).digest())
    msg = str(mac) + msg
    print("\nMessage MAC:" + str(mac))
    print("Message with MAC:" + msg)

    # DES_ECB
    des_key = local.cwrK
    print("DES key：" + str(des_key))
    des = DES.new(des_key, DES.MODE_ECB)
    padded_text = pad(msg)
    encrypted_text = des.encrypt(padded_text.encode("utf-8"))
    print("DES encrypted text：" + str(encrypted_text))
    clientSocket.send(encrypted_text)


if __name__ == "__main__":
    c_local = TLS_helper.Local()
    c_hello = client_hello()
    c_local.hello = c_hello
    c_local.client_random = c_local.hello.random
    c_local = after_serverHelloDone(c_local)
    client_certificate()
    client_key_exchange(c_local)
    c_local = TLS_helper.gene_sessionkey(c_local)
    send_message(c_local)
    clientSocket.close()
