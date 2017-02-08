#-*- encoding=UTF-8 -*-
import sys
from Crypto.Cipher import AES
import binascii
import codecs
def comple(text):
    #bytes(text) convert to bytes but complementary to 16 length
    '''
    print("明码是:",text)
    print("str 长度是:",len(text))
    print("bytes 是:",plaintext)
    print("bytes 长度是:",len(plaintext))
    print()
    '''
    block_size=16
    padding_length = (block_size - len(text) % block_size) % block_size
    if padding_length>0: padded = text + (b'\0')*padding_length
    else:padded = text

    '''
    print("补足后，bytes是:",padded)
    print("补足后，bytes长度是:",len(padded))
    print("补足后，str是:",padded.decode('utf-8'))
    print("补足后，str长度是:",len(padded))
    '''
    return padded

class prpcrypt():
        
    def __init__(self, key, iv = None):
        if(iv == None):
            iv = key
        if(len(key)!=16 or len(iv)!=16):
            print("key or iv length error!")
            #key = input("please enter a 16-length string")
            raise Exception
        self.key = key
        self.mode = AES.MODE_CBC
        self.iv = iv

    def encrypt(self, text):
        #bytes(text) encode to bytes
        cryptor = AES.new(self.key, self.mode, self.iv)
        text_p = text + b'\1'
        padded = comple(text_p)
        self.ciphertext = cryptor.encrypt(padded)
        return binascii.hexlify(self.ciphertext)
     
    def decrypt(self, text):
        #bytes(text) decode to bytes
        cryptor = AES.new(self.key, self.mode, self.iv)
        plain_text_p = cryptor.decrypt(binascii.unhexlify(text))
        plain_text = (plain_text_p.rstrip(b'\0'))[:-1]
        #print(plain_text_p)
        #print(plain_text)
        return plain_text


if __name__ == '__main__':
    BUFSIZE = 1024
    e = prpcrypt('qwerasdfzxcvqazx', 'qweqweqweqweqweq')
    #fp = codecs.open('C:\\Users\\lenovo\\Desktop\\Perl1008.docx','rb')
    #filedata = fp.read(BUFSIZE - 1)
    s = ('asdxfcv').encode('utf-8')
    es = e.encrypt(s)
    ds = e.decrypt(es)
    print(s)
    print(es)
    print(ds)
    print(len(s))
    print(len(es))
    print(len(ds))
