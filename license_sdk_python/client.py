
import base64
import json
import threading
import time

import requests
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
import websocket
import queue

unpad = lambda s: s[:-s[-1]]

class Module(object):
    def __init__(self, key, name, issuedTime, expireTime, extra, childFuncs):
        self.key = key
        self.name = name
        self.issuedTime = issuedTime
        self.expireTime = expireTime
        self.extra = extra
        self.childFuncs = childFuncs

class InitRes(object):
    result: bool
    msg: str
    def __init__(self, result: bool, msg: str):
        self.result = result
        self.msg = msg

_public_key = '9703919fcd22d32a13bb00fba33a2dd0d35746a597f7c5a4843c567c3482c204'


class Client(object):
    publicKey: str
    module: Module
    q = queue.Queue()
    flag = False
    # endPoint: 服务地址，prodKey: 标品唯一标识
    def __init__(self, endPoint: str, prodKey: str):
        self.endPoint = endPoint
        self.prodKey = prodKey

    def init(self):
        res = InitRes(False, '')
        # 1. 获取公钥
        pubkeyResp = self.request(f'http://{self.endPoint}/pubkey?prodkey={self.prodKey}', 'GET', { 'Content-Type': 'application/json'}, None)    
        if (pubkeyResp["code"] != 200):
            msg = f'failed to get auth info: {pubkeyResp}'
            print(msg)
            res.msg = pubkeyResp['msg']
            return res
        
        # 2. AES解密返回的数据
        decryptRes = self.aes_ECB_decrypt(pubkeyResp['data'], _public_key[:32])
        decryptRes = json.loads(decryptRes)

        if (decryptRes['prodKey'] != self.prodKey):
            msg = f'prodkey not match'
            print(msg)
            res.msg = msg
            return res

        self.publicKey = decryptRes['publicKey']

        # 3. 获取权限树
        modulesResp = self.request(f'http://{self.endPoint}/modules?prodkey={self.prodKey}', 'GET', { 'Content-Type': 'application/json'}, None)
        if (modulesResp['code'] != 200):
            msg = f'failed to get modules : {modulesResp['msg']}'
            print(msg)
            res.msg = msg
            return res
        
        try:
            module = self.verifyModuleMsg(modulesResp['data'])
            self.module = module
            res.result = True

            # websocket监听消息
            t1 = threading.Thread(target=self.producer)
            t2 = threading.Thread(target=self.consumer)
            t1.start()
            t2.start()
            self.q.join()
            return res
        except InvalidSignature as e:
            res.msg = e
            return res

    def on_message(self, ws, message):
        print(f"Received message: {message}")
        self.module = self.verifyModuleMsg(json.loads(message))
    
    def on_error(self, ws, error):
        print(f"ws Error: {error}")
    
    def on_close(self, ws, close_status_code, close_msg):
        print("### ws closed ###")
    
    def on_open(self, ws):
        print("### ws Connection opened ###")
        # 发送消息到服务器，例如：
        # ws.send("Hello, Server!")

    def handleWebSocket(self):
        websocket.enableTrace(True)
        ws = websocket.WebSocketApp(f'ws://{self.endPoint}/ws?prodkey={self.prodKey}',
                                    on_open=self.on_open,
                                    on_message=self.on_message,
                                    on_error=self.on_error,
                                    on_close=self.on_close)
        ws.run_forever()

    def producer(self):
        self.q.put('ws')

    def consumer(self):
        while True:
            item = self.q.get()
            self.q.task_done()
            if (item == 'ws'):
                self.handleWebSocket()
                break

    def verifyModuleMsg(self, modulesResp):
        return self.verifySign(self.publicKey, modulesResp['sign'], modulesResp['msg'])


    def verifySign(self, key: str, sign: str, msg: str):
        pubk = bytes.fromhex(key)
        public_key = Ed25519PublicKey.from_public_bytes(pubk)

        try:
            msg = base64.b64decode(msg)
            sign = base64.b64decode(sign)
            public_key.verify(sign, msg)
            print("signature is ok")
            return json.loads(msg.decode())
        except InvalidSignature as e:
            print("signature is bad!", e)
            raise e
    
    def aes_ECB_decrypt(self, data, key):
        key = key.encode('utf-8')
        aes = AES.new(key=key, mode=AES.MODE_ECB)  # 创建解密对象

        # decrypt AES解密  B64decode为base64 转码
        result = aes.decrypt(base64.b64decode(data))
        result = unpad(result)  # 除去补16字节的多余字符
        return str(result, 'utf-8')  # 以字符串的形式返回


    def request(self, url: str, method: str, headers: object|None, body: object|None):
        if (body == None):
            body = ''
        else:
            body = json.dumps(body, ensure_ascii=False, separators=(',', ':'))
        response = requests.request(method, url, headers=headers, data=body)
        return json.loads(response.text)    

    def getModules(self):
        return self.module
    
    def getModule(self, key: str):
        return self.getModuleByKey(self.module, key)
    
    def getModuleByKey(self, module: Module, key: str):
        if (module == None):
            return None
        if (key == module['key']):
            return module
        if (module['childFuncs'] == None):
            return None
        for md in module['childFuncs']:
            ans = self.getModuleByKey(md, key)
            if (ans != None):
                return ans
        return None
    
    def validate(self, key: str) -> bool:
        module = self.getModuleByKey(self.module, key)
        if (module == None):
            return False
        now = time.time()
        if (module['expireTime'] < now):
            return False
        if (module['issuedTime'] > now):
            return False
        return True
    
    def getRemainingDays(self) -> int:
        expireTime = self.module['expireTime']
        return int((expireTime - time.time()) / 3600 / 24) 
 