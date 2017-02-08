#-*- encoding=UTF-8 -*-
import os
import binascii
import codecs
from Crypto.Hash import MD5
from Crypto import Random
from datetime import datetime

def private_key_gene(Username):      
       
    timeNow = datetime.now()
    h = MD5.new()
    h.update((str(timeNow) + str(Username)).encode('utf-8'))
    key = h.hexdigest()
    q = MD5.new()
    q.update((str(Username) + str(timeNow)).encode('utf-8'))
    iv = q.hexdigest()
    return (key[:16], iv[:16])

if __name__ == '__main__':
    private_key = private_key_gene(b'asdasd')
    print(private_key)
