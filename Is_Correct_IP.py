#!/usr/bin/env python
#-*- coding:utf-8 -*-
import re
def Is_Correct_IP(ip):
    p1 = re.compile('\s')
    p2 = re.compile('^(?:(?:[01]?\d{1,2}|2[0-4]\d|25[0-5])\.){3}(?:[01]?\d{1,2}|2[0-4]\d|25[0-5])$') 
    ip_f = p1.sub('', ip)
    res = p2.fullmatch(ip_f)
    if(res == None):
        return False
    else:
        return True
if __name__ == '__main__':
    if(Is_Correct_IP('12  7 .0.2 33. 25  5n')):
        print('yes')
    else:
        print("no")
