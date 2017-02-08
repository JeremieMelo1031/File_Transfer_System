import sqlite3
import time
import traceback
def exe_limit(filename, Database, pid):
    if(pid == 0):#父进程
        def create_table(Database):
            conn = sqlite3.connect(Database)
            cu = conn.cursor()
            sql1 = '''create table if not exists
                         file_exe_table(filename varchar(64), state varchar(8))
                   '''
            conn.execute(sql1)
            conn.commit()
            conn.close()
        create_table(Database)
        conn = sqlite3.connect(Database)
        cu = conn.cursor()
        sql1 = """SELECT COUNT(*) FROM file_exe_table WHERE filename = ? """  
        cu.execute(sql1, (filename,))
        res = cu.fetchone()[0]
        print(res)
        conn.commit()
        if(res < 1):
            try:
                sql2 = '''INSERT INTO file_exe_table(filename, state) values(?, ?)'''
                conn.execute(sql2, (filename, 'inqueue'))
                print("res<1")
            except:
                traceback.print_exc()
            conn.commit()
            conn.close()
            return True
        else:
            conn.close()
            return False
    else:#子进程
        try:
            conn = sqlite3.connect(Database)
            cu = conn.cursor()
            sql3 = """DELETE FROM file_exe_table WHERE filename = ?"""
            cu.execute(sql3, (filename,))
            conn.commit()
            conn.close()
        except:
            return False
        else:
            return True
        
