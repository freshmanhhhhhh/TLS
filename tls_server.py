import base64
import hmac
import os
import subprocess
from hashlib import sha256
from socket import *
import secrets
import time

from Crypto.Cipher import DES
from tinyec import ec

import TLS_helper
import ECDH

# help to read field from client_hello
Version = 0
Random = 1
Sid = 2
CipherS = 3
ComM = 4

# create socket
serverPort = 1234
serverSocket = socket(AF_INET, SOCK_STREAM)  # 创建TCP欢迎套接字，使用IPv4协议
serverSocket.bind(('', serverPort))  # 将TCP欢迎套接字绑定到指定端口
serverSocket.listen(1)  # 最大连接数为1
print("The server in ready to receive")


def server_hello(server_local):
    print("-----Handshake Protocol: Server Hello-----")
    server_local.client_random = connectionSocket.recv(1024)
    server_local.client_random = int.from_bytes(server_local.client_random, 'little')

    client_hello = connectionSocket.recv(1024).decode()  # 获取客户发送的字符串
    helloList = client_hello.split('\n')
    s_hello = TLS_helper.Hello()
    s_hello.version = helloList[Version].split("Version: ")[1]
    s_hello.random = secrets.randbits(256)
    server_local.server_random = s_hello.random
    connectionSocket.send(s_hello.random.to_bytes(32, 'little'))
    time.sleep(0.1)

    s_hello.session_id = helloList[Sid].split("Session ID: ")[1]
    s_hello.cipher_suites = helloList[CipherS].split("Cipher Suite: ")[1]
    s_hello.compression_methods = "null"
    display = "Version: " + s_hello.version + "\n"
    display += "Random: " + str(s_hello.random) + "\n"
    display += "Session ID: " + str(s_hello.session_id) + "\n"
    display += "Cipher Suite: " + s_hello.cipher_suites + "\n"
    display += "Compression Methods: " + s_hello.compression_methods + "\n"
    print(display)
    connectionSocket.send(display.encode())
    server_local.hello = s_hello
    print("Negotiated Cipher Suite: " + s_hello.cipher_suites)
    return server_local


def server_certificate():
    print("\n-----Handshake Protocol: Server Certificate-----")
    cert_fp = "serverKey/server.crt"
    s_cert = open(cert_fp).read()
    connectionSocket.send(s_cert.encode())
    # time.sleep(0.5)
    print("send server certificate over\n")


def server_key_exchange():
    print("-----Handshake Protocol: Server Key Exchange(ECDH)-----")
    # ECDH
    s_ECDHpara = ECDH.ECDHPara()
    s_ECDHpara = ECDH.genekey(s_ECDHpara)
    pkey = s_ECDHpara.pubKey
    # 发送服务器公钥的x,y坐标
    connectionSocket.send(hex(pkey.x).encode())
    time.sleep(0.5)
    connectionSocket.send(hex(pkey.y).encode())
    time.sleep(0.5)
    print("compressed server pkey: " + ECDH.compress(pkey))
    print("server key exchange over\n")
    return s_ECDHpara


def server_certificate_request():
    print("-----Handshake Protocol: Certificate Request-----")
    req = "Certificate Request: 1\n"
    connectionSocket.send(req.encode())
    print("send server certificate request over\n")


def server_hello_done():
    print("-----Handshake Protocol: Server Hello Done-----")
    done = "Server Hello Done\n"
    connectionSocket.send(done.encode())
    print(done)


def client_cert_verify(server_local):
    # RECV SERVER CERTIFICATE
    # verify server certificate
    print("[RECEIVED CLIENT CERTIFICATE]")
    c_cert = connectionSocket.recv(5000).decode()
    c_fp = "client.crt"
    # if this file exists, delete it
    current_path = os.getcwd()
    path = current_path + c_fp
    if os.path.exists(path):
        os.remove(path)
    # create and write client.crt
    f = open(c_fp, "a")
    f.write(c_cert)
    f.close()
    # verify server.crt in command line
    cmd = "openssl verify -CAfile c_ca.crt client.crt"
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    process.wait()
    cmd_output = process.stdout.read().decode('utf-8')
    print("[IS SERVER CERTIFICATE VERIFIED]")
    print("input command : openssl verify -CAfile c_ca.crt client.crt")
    print("output: " + cmd_output)
    if "client.crt: OK" in cmd_output:
        server_local.ispeer_cert_ok = 1
    else:
        print("invalid client certificate, end the connection! ")
        connectionSocket.close()
    return server_local


def server_compute_sharedkey(server_local):
    print('[RECEIVE CLIENT ECDH PUBKEY]')
    ecdhpara = server_local.keyexPara
    # receive (x,y) of server_pubkey
    ecdhpara.peer_key_x = connectionSocket.recv(1024).decode()
    time.sleep(0.5)
    ecdhpara.peer_key_y = connectionSocket.recv(1024).decode()
    # compute ECDH server_pubkey from its (x,y)
    x = int(ecdhpara.peer_key_x.split('0x')[1], 16)
    y = int(ecdhpara.peer_key_y.split('0x')[1], 16)
    ecdhpara.peer_pkey = ec.Point(ecdhpara.curve, x, y)
    print("client pubkey: " + ECDH.compress(ecdhpara.peer_pkey))
    ecdhpara = ECDH.set_shared_key(ecdhpara)
    print("shared key: " + str(ecdhpara.sharedKey))
    server_local.keyexPara = ecdhpara
    return server_local


def receive_message(local):
    print("\n------Test: Receive MSG------")
    encrypted_text = connectionSocket.recv(1024)
    # DES decryption
    des_key = local.cwrK
    print("DES key：" + str(des_key))
    des = DES.new(des_key, DES.MODE_ECB)
    plain_text = des.decrypt(encrypted_text).decode().rstrip(' ')
    print("DES decrypted text：" + plain_text)
    recv_mac = plain_text[:47]
    print("Received MAC:" + recv_mac)
    message = plain_text[47:]
    # compare received MAC to computed MAC
    # if they don't match, the msg is tampered
    mess_mac = base64.b64encode(hmac.new(local.cMacK, message.encode(), digestmod=sha256).digest())
    print(" Message MAC:" + str(mess_mac))
    if str(mess_mac) != recv_mac:
        print("\n[!]MAC don't match.\nTampered Message!!!!!")
    else:
        print("\n[√]Right MAC! Authentic Message!")
        print("[√]Message:" + message)


if __name__ == "__main__":
    connectionSocket, addr = serverSocket.accept()  # 接收到客户连接请求后，建立新的TCP连接套接字
    s_local = TLS_helper.Local()
    s_local.isReq = 1  # 服务器的证书是必需的
    s_local = server_hello(s_local)
    server_certificate()
    s_local.keyexPara = server_key_exchange()
    server_certificate_request()
    server_hello_done()
    s_local = client_cert_verify(s_local)
    s_local = server_compute_sharedkey(s_local)
    s_local = TLS_helper.gene_sessionkey(s_local)
    receive_message(s_local)
    connectionSocket.close()  # 关闭TCP连接套接字
