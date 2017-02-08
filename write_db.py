
import sys
import hashlib
import getpass
import sqlite3
import encode_decode
from reg_limit import limit_ip
import time
processor = encode_decode.prpcrypt(key = "qwerasdfzxcvqazx")
def user_info(Username, Code):#对已经在客户端加密过的用户名和密码再次加密准备写入数据库
    info = []
    Password = hashlib.sha224(Code).hexdigest()
    info.append((Username, Password))
    return info


def write_db(ip, Username, Code, Database_write = 'pub.db', Database_limit = 'limit.db'):#传递参数为数据库路径，收到的用户名（客户端已加密），密码（客户端已加密）
        info = user_info(Username, Code)
        conn = sqlite3.connect(Database_write)
        sql_ex = '''
                 create table if not exists
                 Info(id integer primary key
                 autoincrement,username varchar(64),code varchar(64))
        '''
        conn.execute(sql_ex)
        conn.commit()
        cur = conn.cursor()
        sql = '''
          select username,code from Info where username = ?
          '''
        cur.execute(sql, (Username,))
        try:
            uname, pw = cur.fetchone()
        except:
            sql ="insert into Info(username, code) values (?,?)"
            conn.execute(sql, info[0])
            conn.commit()      
            cur.close()
            conn.close()
            #sign up成功后在limit数据库添加IP记录。
            conn2 = sqlite3.connect(Database_limit)
            cur2 = conn2.cursor()
            now = time.time()
            sql2 = """INSERT INTO ip_table(ip, access_time) values(?, ?)"""
            cur2.execute(sql2, (ip, now))
            conn2.commit()
            cur2.close()
            conn2.close()
            
            return True        #说明用户创建成功
        print("用户名已存在")
        cur.close()
        conn.close()
        return False        #说明用户名已存在，返回创建失败
if __name__ == "__main__":
        if(write_db(processor.encrypt('jeremiemelo'.encode('utf-8')),processor.encrypt('123456789'.encode('utf-8'))) == True):
            print("yes")
        else:
            print("fail")
