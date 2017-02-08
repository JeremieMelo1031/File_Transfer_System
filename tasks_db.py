import sqlite3
import traceback
import os
import sys
import time
def add_tasks(filedir, state, time, Username, rootdir = '/usr/local', result_filedir = '', Database = None):
    if(Database == None):
        Database = rootdir + '/' + Username + '/' + 'tasks.db'
    if(not os.path.isfile(filedir)):
        return 'nofile'
    filesize = os.stat(filedir).st_size
    def create_table( Database = None):
        
        conn = sqlite3.connect(Database)
        cu = conn.cursor()
        sql1 = '''create table if not exists
                     tasks(id integer primary key
                     autoincrement,
                     filedir varchar(128),
                     state varchar(12),
                     filesize varchar(16),
                     time varchar(32),
                     result_filedir varchar(128),
                     result_filesize varchar(16))
               '''
        conn.execute(sql1)
        conn.commit()
        conn.close()
        
    try:
        create_table(Database)
        conn = sqlite3.connect(Database)
        cu = conn.cursor()
        sql1 = """INSERT INTO tasks(filedir, state, filesize, time, result_filedir, result_filesize) VALUES (?,?,?,?,?,?)"""
        if(state == 'inqueue'):
            conn.execute(sql1, (filedir, state, filesize, time, '', 0))
        elif(state == 'processing'):
            conn.execute(sql1, (filedir, state, filesize, time, '', 0))
        elif(state == 'finished'):
            if(not os.path.isfile(result_filedir)):
                conn.close()
                return 'no_result_file'
            else:
                result_filesize = os.stat(result_filedir).st_size
                conn.execute(sql1, (filedir, state, filesize, time, result_filedir, result_filesize))
        conn.commit()
    except Exception as e:
        traceback.print_exc()
        conn.close()
        return 'add_fail'
    else:
        sql2 = '''SELECT id FROM tasks WHERE filedir = ? and state = ? and time = ?'''
        cur = conn.cursor()
        cur.execute(sql2, (filedir, state, time))
        task_id = cur.fetchone()[0]
        conn.close()
        return task_id

def get_a_task(id,  filedir, Username, state = 'finished', rootdir = '/usr/local',Database = None):#读取所有特定state的记录,默认finished,返回一个列表，内部记录是元组
    
    
    if Database == None:
        Database = rootdir + '/' + Username + '/' + 'tasks.db'
    def create_table(Database = None):
        
        conn = sqlite3.connect(Database)
        cu = conn.cursor()
        sql1 = '''create table if not exists
                     tasks(id integer primary key
                     autoincrement,
                     filedir varchar(128),
                     state varchar(12),
                     filesize varchar(16),
                     time varchar(32),
                     result_filedir varchar(128),
                     result_filesize varchar(16))
               '''
        conn.execute(sql1)
        conn.commit()
        conn.close()
        
    try:
        create_table(Database)
        conn = sqlite3.connect(Database)
        
        cu = conn.cursor()
        sql1 = """SELECT * FROM tasks WHERE id = ? and filedir = ? and state = ?"""
        sql2 = """DELETE FROM tasks WHERE filedir = ? and state = ?"""
        cu.execute(sql1, (id, filedir, state,))
        task = cu.fetchone() 
        print(task)
        conn.commit()
        
    except Exception as e:
        traceback.print_exc()
        conn.close()
        return 'get_fail'
    else:
        cu.close()
        conn.close()
        return task
    
        
def get_tasks( Username, state = 'finished', rootdir = '/usr/local',Database = None):#读取所有特定state的记录,默认finished,返回一个列表，内部记录是元组
    
    
    if Database == None:
        Database = rootdir + '/' + Username + '/' + 'tasks.db'
    def create_table(Database = None):
        
        conn = sqlite3.connect(Database)
        cu = conn.cursor()
        sql1 = '''create table if not exists
                     tasks(id integer primary key
                     autoincrement,
                     filedir varchar(128),
                     state varchar(12),
                     filesize varchar(16),
                     time varchar(32),
                     result_filedir varchar(128),
                     result_filesize varchar(16))
               '''
        conn.execute(sql1)
        conn.commit()
        conn.close()
        
    try:
        create_table(Database)
        conn = sqlite3.connect(Database)
        
        cu = conn.cursor()
        sql1 = """SELECT * FROM tasks WHERE state = ?"""
        sql2 = """DELETE FROM tasks WHERE filedir = ? and state = ?"""
        cu.execute(sql1, (state,))
        tasks = cu.fetchall() 
        print(tasks)
        conn.commit()
        
    except Exception as e:
        traceback.print_exc()
        conn.close()
        return 'get_fail'
    else:
        cu.close()
        conn.close()
        return tasks

def delete_tasks(id, filedir, Username, state = 'finished', rootdir = '/usr/local',Database = None):
    if Database == None:
        Database = rootdir + '/' + Username + '/' + 'tasks.db'
    def create_table(Database = None):
        
        conn = sqlite3.connect(Database)
        cu = conn.cursor()
        sql1 = '''create table if not exists
                     tasks(id integer primary key
                     autoincrement,
                     filedir varchar(128),
                     state varchar(12),
                     filesize varchar(16),
                     time varchar(32),
                     result_filedir varchar(128),
                     result_filesize varchar(16))
               '''
        conn.execute(sql1)
        conn.commit()
        conn.close()
        
    try:
        create_table(Database)
        conn = sqlite3.connect(Database)
        
        cu = conn.cursor()
        sql2 = """DELETE FROM tasks WHERE id = ? and filedir = ? and state = ?"""
        cu.execute(sql2, (id, filedir, state))
        conn.commit()
    except Exception as e:
        traceback.print_exc()
        cu.close()
        conn.close()
        return 'delete_fail'
    else:
        cu.close()
        conn.close()
        return True


        
def count_tasks(filedir,  Username, state, rootdir = '/usr/local',Database = None):#根据任务文件路径和任务状态来搜寻任务数目
    
    
    if Database == None:
        Database = rootdir + '/' + Username + '/' + 'tasks.db'
    def create_table(Database = None):
        
        conn = sqlite3.connect(Database)
        cu = conn.cursor()
        sql1 = '''create table if not exists tasks(id integer primary key autoincrement,
                 filedir varchar(128),
                 state varchar(12),
                 filesize varchar(16),
                 time varchar(32),
                 result_filedir varchar(128),
                 result_filesize varchar(16))
               '''
        conn.execute(sql1)
        conn.commit()
        conn.close()
        
    try:
        create_table(Database)
        conn = sqlite3.connect(Database)
        cu = conn.cursor()
        sql3 = """SELECT COUNT(*) FROM tasks WHERE filedir = ? and state = ?"""
        cu.execute(sql3, (filedir, state))
        num = cu.fetchone()[0]
        conn.commit()
        
    except Exception as e:
        traceback.print_exc()
        return 'count_fail'
    else:
        return num
    finally:
        conn.close()
        
if __name__ == '__main__':
    t = time.ctime()#time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.localtime())
    print(t)
   # print(add_tasks(r'E:\test\chinese.py', 'inqueue', t, r'jeremie', r'E:\test', Database = r'E:\test\tasks.db'))
##    get_tasks(r'jeremie', 'inqueue', r'E:\test', r'E:\test\tasks.db')
##    delete_tasks(2, r'E:\test\chinese.py', r'jeremie', 'inqueue', r'E:\test', r'E:\test\tasks.db')
    num = count_tasks(r'E:\test\chinese.py', r'jeremie', 'inqueue', r'E:\test', r'E:\test\tasks.db')
    print(num)
