import sqlite3
import time

    
def limit_ip(ip, now, Database = "limit.db", IP_COLD_TIME = 1200, IP_MAX_ACCESS_TIMES = 2):#now是访问时刻的unix时间   
  
    """   
 
    return True if need to limit ip,otherwise return False  
 
    @ip: ip address that is 'xxx.xxx.xxx.xxx'  
 
    @now: unix time, int  
 
    """
    def create_table(Database = "limit.db"):
        conn = sqlite3.connect(Database)
        cu = conn.cursor()
        sql1 = '''create table if not exists
                     ip_table(id integer primary key
                     autoincrement,ip varchar(20),access_time int)
               '''
        conn.execute(sql1)
        conn.commit()
        conn.close()
    create_table(Database)
    conn = sqlite3.connect(Database)
    cu = conn.cursor()
    sql1 = """SELECT COUNT(*) FROM ip_table WHERE ip = ? and access_time > ? and access_time < ?"""  
    sql2 = """DELETE FROM ip_table WHERE ip = ? and access_time <= ?"""
    conn.execute(sql2, (ip, now - IP_COLD_TIME))#删除超过冷却时间的历史记录，以清除储存空间
    cu = conn.cursor()
    cu.execute(sql1, (ip, now - IP_COLD_TIME, now))#查询冷却时间内的申请次数
    access_times = cu.fetchone()[0]
    print(access_times)
    conn.commit()
    conn.close()
    if access_times < IP_MAX_ACCESS_TIMES and access_times >= 0:
        return False  
    return True

now = time.time()
Database = 'limit.db'
if(not limit_ip("127.0.0.1", now)):
    conn = sqlite3.connect(Database)
    cu = conn.cursor()
    sql = """INSERT INTO ip_table(ip, access_time) values(?, ?)"""
    cu.execute(sql, ("127.0.0.1", now))
    conn.commit()
    conn.close()
print(limit_ip("127.0.0.1", now))
