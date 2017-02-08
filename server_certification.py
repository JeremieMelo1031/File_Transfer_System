import sys
import hashlib
import getpass
import sqlite3
 
def certification(Username, Code, Database = 'pub.db'):#用于验证用户信息，顺便查看用户是否存在，参数：数据库路径，用户名（客户端已加密）、密码（客户端已加密）
    
    conn = sqlite3.connect(Database)
    cu = conn.cursor()
    sql = '''
          select username,code from Info where username = ?
          '''
    cu.execute(sql, (Username,))
    try:
        uname,pw = cu.fetchone()
    except (TypeError) as e:
        print("用户名不存在")
        return 'nonexist'
    Password = hashlib.sha224(Code).hexdigest()
    if Password != pw:
         print( 'Incorrect Password,\n')
         return 'fail'
    else:
        return 'success'
        sys.exit()
 
if __name__ == "__main__":
    res = certification('acv','asdasd')
    if(res == 'fail'):
        print("fail")
    elif(res == 'nonexist'):
        print("nonexist")
    else:
        print("success")
