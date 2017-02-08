#! /usr/bin/python
# -*- coding: utf-8 -*-
import re

def if_has_chinese(text):
    zhPattern = re.compile(u'[\u4e00-\u9fa5]+')
    #一个小应用，判断一段文本中是否包含简体中：str(text)
    match = zhPattern.search(text)
    if match:
        return True
    else:
        return False
if __name__ == '__main__':
    text = 'C:\\test\\1.5-'
    if(if_has_chinese(text)):
        print("has")
    else:
        print("no")
