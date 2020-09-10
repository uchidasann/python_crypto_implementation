#py3
from Crypto.Cipher import AES

#AES解密
def AES_dec(key:str, mode, data:bytes, iv=bytes([0]*16))->bytes:
    
    key = key.encode('utf-8')    #str转bytes
    if(mode == AES.MODE_ECB):
        cryptor = AES.new(key, mode)
    else:
        cryptor = AES.new(key, mode, iv)
    
    return cryptor.decrypt(data)

#AES加密
def AES_enc(key:string, mode, data:bytes, iv=beytes([0]*16))->bytes:
    key = key.encode('utf-8')    #str转bytes
    if(mode == AES.MODE_ECB):
        cryptor = AES.new(key, mode)
    else:
        cryptor = AES.new(key, mode, iv)
    
    return cryptor.encrypt(data)
