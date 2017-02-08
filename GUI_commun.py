#-*- encoding=UTF-8 -*-
import socket 
import os
import encode_decode
import sys
import struct
import binascii
import codecs
from mtTkinter.mtTkinter import *
from tkinter.ttk import *
from ScrolledText import ScrolledText
from chinese import if_has_chinese
from Is_Correct_IP import Is_Correct_IP
from system_disk import system_disk
import time
import rsa
from time import clock
import glob
import traceback
from tkinter.filedialog import askopenfilename, askdirectory
import messagebox
import threading
from apscheduler.schedulers.background import BackgroundScheduler
import queue
global private_key
global private_iv
global server_dir_hash
global usr_root_dir
global server_rsa_pubkey
global client_rsa_prikey

processor = encode_decode.prpcrypt(key = "qwerasdfzxcvqazx")
server_dir_hash = {}
private_key = ''
private_iv = ''
server_rsa_pubkey = b''
client_rsa_prikey = b''
sendfile = processor.encrypt('sendfile'.encode('utf-8'))
senddir = processor.encrypt('senddir'.encode('utf-8'))
intodir = processor.encrypt('intodir'.encode('utf-8'))
success = processor.encrypt('success'.encode('utf-8'))
fail = processor.encrypt('fail'.encode('utf-8'))
limit = processor.encrypt('limit'.encode('utf-8'))
exist = processor.encrypt('exist'.encode('utf-8'))
nonexist = processor.encrypt('nonexist'.encode('utf-8'))
login = processor.encrypt('login'.encode('utf-8'))
signup = processor.encrypt('signup'.encode('utf-8'))
disconnect = processor.encrypt('disconnect'.encode('utf-8'))
download = processor.encrypt('download'.encode('utf-8'))

root = Tk()
root.title("File Transport Service")
root.geometry('1000x600+300+50')
root.maxsize(1200,600)
root.minsize(1000,600)
mainframe = Frame(root)
mainframe.grid(row = 0, column = 0, ipadx = 850, ipady = 600)
menubar = Menu(root)
separator1 = Separator(mainframe, orient='vertical')
separator1.grid(row = 0, column = 1, sticky=(N, S), ipady = 600)
#框架frm_u
frm_u= Frame(mainframe)
frm_u.grid(row = 0, column = 0,sticky=(N, W, E, S))
#框架frm_s
frm_s= Frame(mainframe)
frm_s.grid(row = 0, column = 2,sticky=(N, W, E, S))
#推送显示栏
frm_p = Frame(mainframe)
frm_p.grid(row = 0, column = 3, sticky = (N, W, E, S))
#左上层框架frm_u1
frm_u1= Frame(frm_u)
frm_u1.grid(row = 0, column = 0)
#用户label
label1=Label(frm_u1, text = "Current User")
label1.grid(row = 0, column = 0, padx = 10,  pady = 10,sticky = W)
#用户登录状态
userlist=Entry(frm_u1, width = 25)#, yscrollcommand = sl_1.set)#行数来控制，单位并非是像素
userlist.grid(row = 0, column = 1,pady = 10, sticky = W)
userlist['state'] = 'disabled'
#选择文件label
label2= Label(frm_u1, text="Choose Files")
label2.grid(row = 1, column = 0, pady = 10, padx = 10, sticky = W)
#路径显示文本框
Text_clientpath=Entry(frm_u1,width=30)
Text_clientpath.grid(row = 1, column = 1, pady = 10, sticky = W, columnspan = 2)
#进度百分比
label5=Label(frm_u1, text = '', width = 4)
label5.grid(row = 0, column = 2, padx = 4,  pady = 10,sticky = W)
#进度条
ProgressBar = Progressbar(frm_u1,  value = 0, orient = 'horizontal', length = 163, maximum = 100, mode = 'determinate')
ProgressBar.grid(row = 0, column = 3, columnspan = 3, sticky = W)
frm_u2= Frame(frm_u) 
frm_u2.grid(row = 1, column = 0)
def BFS_Dir(root):
    dirlist = [root]
    for i in glob.glob(root + '/*'):
        dirlist.append(i)
    return dirlist


    
def insert_tree_node(tree, path):#在tree中添加path，path为服务器中完整路径
    root_path = '/'.join(path.split('/')[:-1])
    node = path.split('/')[-1]
    root_id = tree.get_children()[0]
    current_tree_root = tree.item(root_id, "values")[0]
    current_tree_children_id = tree.get_children(root_id)
    current_tree_children = [tree.item(iid, "values")[0] for iid in current_tree_children_id if tree.item(iid, "values") != '']
    if(root_path == current_tree_root and node not in current_tree_children):
        oid = tree.insert(root_id, 'end', text = node, values = node)
    if(root_path in server_dir_hash):#path根目录有缓存过
        if(path not in server_dir_hash[root_path]):
            server_dir_hash[root_path].append(path)
            return True
    return False

def build_tree(tree, path):
    root_dir = path[0]
    root_node = tree.insert('', 'end', text = root_dir,values = root_dir, open = True)
    for p in path[1:]:
        #构建路径
        if(p == ''):
            continue
        if(root_dir != '/'):
          root_length = len(root_dir)
          p = p[root_length + 1:]
        oid = tree.insert(root_node, 'end', text = p, values = p)
            
def delete_tree(tree):
    try:
        parent = tree.get_children()
        children = tree.get_children(parent)
        for child in children:
            tree.delete(child)
            tree.update()
        tree.delete(parent)
    except:
        pass
    

        
#客户端目录树
system_root = system_disk()
Dir_Tree1 = Treeview(frm_u2)
ysb1 = Scrollbar(Dir_Tree1, orient='vertical', command=Dir_Tree1.yview)
xsb1 = Scrollbar(Dir_Tree1, orient='horizontal', command=Dir_Tree1.xview)
Dir_Tree1.configure(yscroll=ysb1.set, xscroll=xsb1.set)
Dir_Tree1.heading('#0', text='Current Directory', anchor='w')
build_tree(Dir_Tree1, system_root)

def Select_Server_Dir1(event):
    if(Dir_Tree1.selection()):
        item = Dir_Tree1.selection()[0]
        parent_item = Dir_Tree1.parent(item)
        if(parent_item):#选中文件或进入目录，同时选中该目录
            root = Dir_Tree1.item(parent_item, "values")[0]
            if(root != '/'):
                select_dir = ' '.join(Dir_Tree1.item(item, "values"))
                abs_dir = '/'.join([root, select_dir])
            else:
                select_dir = ' '.join(Dir_Tree1.item(item, "values"))
                abs_dir = select_dir
        
            Text_clientpath['state'] = NORMAL
            Text_clientpath.delete('0', END)
            Text_clientpath.insert('end', abs_dir)
            if(os.path.isdir(abs_dir)):
                files = BFS_Dir(abs_dir)
                delete_tree(Dir_Tree1)
                build_tree(Dir_Tree1, files)
        else:#返回
            select_dir = ' '.join(Dir_Tree1.item(item, "values"))
            root = '/'.join(select_dir.split('/')[:-1])
            if(select_dir in system_root):
                delete_tree(Dir_Tree1)
                build_tree(Dir_Tree1, system_root)
                
            else:
                files = BFS_Dir(root)
                delete_tree(Dir_Tree1)
                build_tree(Dir_Tree1, files)
        
Dir_Tree1.bind("<Double-1>", Select_Server_Dir1)
Dir_Tree1.grid(row = 0, column = 0, sticky = W, ipadx = 200, ipady = 105)
ysb1.pack(side = 'right', fill = 'y', anchor='e')
xsb1.pack(side = 'bottom', fill = 'x',  anchor='s')

#信息显示框
Info1=Text(frm_u2, width = 65, height = 17)
Info1.grid(row = 1, column = 0, sticky = W, pady = 10)
#右边服务器
frm_s1 = Frame(frm_s)
frm_s1.grid(row = 0, column = 0)
#功能选项卡
label3 = Label(frm_s1, text="Options")
label3.grid(row = 0, column = 0,  pady = 10, sticky = W)
###服务器IP地址文本框
##Text_serverIP=Entry(frm_s1,width=28)
##Text_serverIP.grid(row = 0, column = 1, padx = 10,  pady = 10, sticky = W)
##Text_serverIP.focus()

frm_s2 = Frame(frm_s)
frm_s2.grid(row = 1, column = 0)

#服务器的各种按钮
label4= Label(frm_s1, text="Server Path")
label4.grid(row = 1, column = 0,  pady = 8, sticky = W)
#服务器目录显示文本框
Text_serverpath=Entry(frm_s1,width=28)
Text_serverpath['state'] = DISABLED
Text_serverpath.grid(row = 1, column = 1, padx = 10,  pady = 10, sticky = W, columnspan = 2)

def Select_Server_Dir2(event):
    if(Dir_Tree2.selection()):
        item = Dir_Tree2.selection()[0]
        parent_item = Dir_Tree2.parent(item)
        if(parent_item):
            root = Dir_Tree2.item(parent_item, "values")[0]
            select_dir = ' '.join(Dir_Tree2.item(item, "values"))
            abs_dir = '/'.join([root, select_dir])
        else:
            abs_dir = Dir_Tree2.item(item, "values")
        Text_serverpath['state'] = NORMAL
        Text_serverpath.delete('0', END)
        Text_serverpath.insert('end', abs_dir)
    
Dir_Tree2 = Treeview(frm_s2)
ysb2 = Scrollbar(Dir_Tree2, orient='vertical', command=Dir_Tree2.yview)
xsb2 = Scrollbar(Dir_Tree2, orient='horizontal', command=Dir_Tree2.xview)
Dir_Tree2.configure(yscroll=ysb2.set, xscroll=xsb2.set)
Dir_Tree2.heading('#0', text='Current Directory', anchor='w')
Dir_Tree2.bind("<Double-1>", Select_Server_Dir2)   
Dir_Tree2.grid(row = 0, column = 0, sticky = W, ipadx = 200,  padx = 10, ipady = 105)
ysb2.pack(side = 'right', fill = 'y', anchor='e')
xsb2.pack(side = 'bottom', fill = 'x',  anchor='s')
#build_tree(Dir_Tree2, path=[])
#信息显示框
Info2=Text(frm_s2, width = 65, height = 17)
Info2.grid(row = 1, column = 0, sticky = W, padx = 10, pady = 8)
#推送显示卡
notebook = Notebook(frm_p, width = 100, height = 550)
frm_inqueue = Frame(notebook)
frm_processing = Frame(notebook)
frm_finished = Frame(notebook)
notebook.add(frm_inqueue, text = 'in queue', padding = 3)
notebook.add(frm_processing, text = 'processing', padding = 3)
notebook.add(frm_finished, text = 'finished', padding = 3)
Row = 11
Col = 11
Width = 100
table_nme = 'tab One'
element_header = []
for i in range(Col):
    element_header.append(str(i))

element_list = []
for i in range(Row):
    element_list.append([])
    for j in range(Col):
        element_list[i].append(j)
notebook.grid(row = 0, column = 0, sticky = (N, W, E, S))
def CallFiles():   
    dirname = askopenfilename(parent=root,initialdir="/",title='Pick a file')
    Text_clientpath.delete('0',END)
    Text_clientpath.insert("0",dirname)

def CallDir():   
    dirname = askdirectory(parent=root,initialdir="/",title='Pick a directory')
    if(not dirname):
        return False
    Text_clientpath.delete('0',END)
    Text_clientpath.insert("0",dirname)
    return True

def about():

    Info1_Insert( u"Click the User label ==> Enter the server address, username\nand password ==> Login ==>click File to choose a file or click\nCase to choose a filecase ==> choose the server directory ==>\nSend ==> Log out\n")

  
def Cut():

    Info1_Insert(u"I am Cut\n")

def Copy():

    Info1_Insert( u"I am Copy\n")

    
def Paste():

    Info1_Insert(u"I am Paste\n")


    
def select(*args):#路径选择后显示在server directory里
    Text_serverpath['state'] = NORMAL
    Text_serverpath.delete('0', END)
    Text_serverpath.insert('end', serverlistcombo.get())
    Text_serverpath['state'] = DISABLED

def DisableButton():
    SendButton['state'] = DISABLED
    IntoButton['state'] = DISABLED
    BackButton['state'] = DISABLED
    NewButton['state'] = DISABLED
    ExecuteButton['state'] = DISABLED
    RefreshButton['state'] = DISABLED
    DownloadButton['state'] = DISABLED
    
def EnableButton():
    SendButton['state'] = NORMAL
    IntoButton['state'] = NORMAL
    BackButton['state'] = NORMAL
    NewButton['state'] = NORMAL
    ExecuteButton['state'] = NORMAL
    RefreshButton['state'] = NORMAL
    DownloadButton['state'] = NORMAL
    
def Info1_Insert(text):
    Info1['state'] = NORMAL
    Info1.insert('end', text)
    Info1.see(END)
    Info1['state'] = DISABLED
    
def Info2_Insert(text):
    Info2['state'] = NORMAL
    Info2.insert('end', text)
    Info2.see(END)
    Info2['state'] = DISABLED
    

        
global sendSock
sendSock=None
global server_dirlist
server_dirlist = ''
port_list = [8120,8090,10520,20520,30520]
port=8120
BUFSIZE = 32767
RECV_BUFSIZE = 8192
FILEINFO_SIZE=struct.calcsize('128s32sI8s')
threadQueue = queue.Queue()
global lock
lock = threading.Lock()
def threadSendall(sendSock, message):
    try:
        global lock
        global threadQueue
        func_name = sys._getframe().f_code.co_name
        lock.acquire()
        sendSock.sendall(message)
        lock.release()
        threadQueue.put((True, func_name))
        root.update()
    except:
        threadQueue.put((False, func_name))
        traceback.print_exc()
        


#点击Connect按钮连接服务器
def Connect( event = None, host = None,):
    global threadQueue
    if(host == None):
        host=Text_serverIP.get()
    global sendSock
    global server_rsa_pubkey
    Info2_Insert('Scanning the available port., Please wait... '+'\n')
    sendSock= socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    #发出连接请求
    func_name = sys._getframe().f_code.co_name
    #print(func_name)
    for port in port_list:
        try: 
            global lock
            
            sendSock.settimeout(5)
            print(port)
            sendSock.connect((host,port))
            print('link')
            sendSock.settimeout(2)
            server_rsa_pubkey_n_e = sendSock.recv(1024)
            print('there')
            #print("recv server rsa finish")
            Format = "%ds%ds" % (77,5)
            pub_key_n, pub_key_e = struct.unpack(Format, server_rsa_pubkey_n_e)
            server_rsa_pubkey = rsa.PublicKey(int(pub_key_n), int(pub_key_e))
            port_pointer = 0
            lock.acquire()
            Info1_Insert('Connection success to server: ' + host + ' through port: ' + str(port) + '.' + ' Please Log in！\n')
            
            filemenu.entryconfig(0, state = NORMAL)
            filemenu.entryconfig(1, state = NORMAL)
            lock.release()
            threadQueue.put((True, func_name))
            root.update()
            return
        except (ConnectionRefusedError,OSError) as e:
            #Info2_Insert(str(e) + '\n')
            traceback.print_exc()
            Info2_Insert('The port: ' + str(port) +  ' is not available, try another port..'+ '\n')
            root.update()
        except:
            traceback.print_exc()
    port_pointer = 0
    Info2_Insert( 'The server IP cannot be connected now.' + '\n')          
    sendSock = None
    threadQueue.put((False, func_name))
    
   
  

def Login():#实现登录功能
    def recover_root():
        root.attributes("-disabled", 0)
        Win_Login.destroy()
        
    Win_Login = Toplevel(height = 200, width = 400)
    Win_Login.transient(master = root)#永远位于其父窗口之上，伴随父窗口消失而消失
    root.attributes("-disabled", 1)
    Win_Login.title('Log In')
    Win_Login.geometry('400x300+400+150')
    Win_Login.maxsize(400, 300)
    Win_Login.minsize(400, 300)
    Win_Login.protocol(name = "WM_DELETE_WINDOW", func = recover_root)
    def Identification(event = None):
        global private_key
        global private_iv
        global usr_root_dir
        global server_rsa_pubkey
        global client_rsa_prikey
        global threadQueue
        try:
                
            HOST = '192.168.0.106'#text_ip.get().strip()
            if(sendSock == None and Is_Correct_IP(HOST) == False):
                
                messagebox.showinfo(title = 'Fail', message = 'Invalid IP Address')
                #Info1_Insert('Invalid IP Address\n')
                return False
            username = 'asdasdasd'#text_username.get()
            code = '123456789'#text_code.get()
            if(8 <= len(username) <= 15 and 8 <= len(code) <= 15 and not if_has_chinese(username) and not if_has_chinese(code)):
                #首先进行连接尝试
                if(sendSock == None):
                    
                    thread = threading.Thread(target = Connect, args = (None, HOST))
                    thread.setDaemon(True)
                    thread.start()
                    ProgressBar.start()
                    while(1):
                        time.sleep(0.02)
                        root.update()
                        if(threadQueue.empty()):
                            
                            continue
                        result = threadQueue.get()
                        if(result[1] == Connect.__name__):
                            if(result[0] == False):
                                ProgressBar.stop()
                                messagebox.showinfo(title = 'Fail', message = 'Fail to connect to the server\nPlease try again')
                                Info1_Insert('Fail to connect to the server. Please try again\n')
                                return False
                            else:break
                #若连接成功，尝试身份认证,此时加密使用rsa加密
                print('lian jie cheng gong')
                username_e = rsa.encrypt(username.encode('utf-8'), server_rsa_pubkey)
                code_e = rsa.encrypt(code.encode('utf-8'),server_rsa_pubkey)
                Mode_e = rsa.encrypt('login'.encode('utf-8'),server_rsa_pubkey)
                while(1):#密钥生成长度不稳定，可能是77+5=82，也可能是83，因此必须要稳定在82，反复生成。
                    (pub_key, pri_key) = rsa.newkeys(256)
                    pub_key_n, pub_key_e = str(pub_key.n).encode('utf-8'), str(pub_key.e).encode('utf-8')
                    filedata_size = len(pub_key_n + pub_key_e)
                    if(filedata_size != 82):
                        continue
                    else:
                        break
                client_rsa_prikey = pri_key#立即保存客户端的rsa私钥
                DisableButton()
                message = struct.pack("32s32s32ssI2048s", Mode_e, username_e, code_e, '3'.encode('utf-8'), filedata_size, pub_key_n + pub_key_e)
                #发送数据块
                sendSock.settimeout(4)
                sendSock.sendall(message)
                left_data_size = RECV_BUFSIZE
                total_data = b''
                while(left_data_size):
                    recv_data = sendSock.recv(left_data_size)
                    total_data += recv_data
                    recv_size = len(recv_data)
                    left_data_size -= recv_size
                data_size, rest_data = struct.unpack("I8188s", total_data)
                real_data = rest_data[:data_size]
                re_message = eval(real_data.decode('utf-8'))#得到加密后的验证结果、密钥和盐
                certificate = rsa.decrypt(re_message[0], client_rsa_prikey).decode('utf-8')#此时必须用rsa解密，AES密钥能不能取得还是未知数，就算登陆成功，也必须对certificate解密
                EnableButton()
                if(certificate == 'success'):
                    KEY_IV_SIZE = struct.calcsize('16s16s')
                    private_key = rsa.decrypt(re_message[1], pri_key)#AES密钥必须用rsa解密
                    private_iv = rsa.decrypt(re_message[2], pri_key)
                    #print(private_key, private_iv, "aes key iv")
                    pr_processor = encode_decode.prpcrypt(key = private_key, iv = private_iv)#生成AES解码器
                    UserDir = pr_processor.decrypt(re_message[4]).decode('utf-8')#为了保证速度，此处使用的是AES解密，因为之前得到了AES密钥，所以完全没问题
                    current_dir = eval(UserDir.replace('\\\\','/'))
                    build_tree(Dir_Tree2, current_dir )#预先存入根目录
                    usr_root_dir = current_dir[0]
                    server_dir_hash[usr_root_dir] = current_dir
                    filemenu.entryconfig(0, state = DISABLED)
                    filemenu.entryconfig(2, state = NORMAL)
                    Info1_Insert( u'Log in success!\n')
                    userlist['state'] = NORMAL
                    userlist.insert('0', username )
                    userlist['state'] = DISABLED
                    ProgressBar.stop()
                    EnableButton()
                    sendSock.settimeout(None)
                    recover_root()
                    messagebox.showinfo(title = 'Success', message = 'User ' + username + ' logged in')
                    #Info1_Insert('User ' + username + ' logged in\n')
                elif(certificate == 'nonexist'):
                    messagebox.showinfo(title = 'Fail', message = 'Nonexistent Username')
                    #Info1_Insert('Nonexistent Username\n')
                    ProgressBar.finish()
                    sendSock.settimeout(None)
                    Disconnect()
                else:
                    messagebox.showinfo(title = 'Fail', message = 'Wrong password, Try again')
                    #Info1_Insert('Wrong password, Try again\n')
                    ProgressBar.stop()
                    sendSock.settimeout(None)
                    Disconnect()
            else:
                ProgressBar.stop()
                messagebox.showinfo(title = 'Warning', message = 'Invalid username or password')
                
                #Info1_Insert('Invalid username or password\n')
        except Exception as e:
            print(str(e))
            traceback.print_exc()
            Info1_Insert('Logging in failed\n')
            ProgressBar.stop()
            EnableButton()
            if(sendSock != None):
                sendSock.settimeout(None)
            Disconnect()
            recover_root()
            
            
    #基础框架

    #提示label
    label_server_ip = Label(Win_Login, text = 'Server IP', width = 15)
    label_server_ip.grid(row = 0, column = 0, sticky = 'w', padx = 10, pady = 20)
    label_username = Label(Win_Login, text = 'Username', width = 15)
    label_username.grid(row = 1, column = 0, sticky = 'w', padx = 10, pady = 20)
    label_code = Label(Win_Login, text = 'Code', width = 15)
    label_code.grid(row = 2, column = 0, sticky = 'w', padx = 10, pady = 20)
    #输入要求提示
    label_req1 = Label(Win_Login, text = '8-15 characters' )
    label_req1.grid(row = 1, column = 2, sticky = 'w', padx = 10, pady = 20)
    label_req2 = Label(Win_Login, text = '8-15 characters')
    label_req2.grid(row = 2, column = 2, sticky = 'w', padx = 10, pady = 20)
    #输入文本框
    text_ip = Entry(Win_Login, width = 20)
    text_username = Entry(Win_Login, width = 20)
    text_code = Entry(Win_Login, width = 20, show = '*') 
    text_username.grid(row = 1, column = 1, sticky = 'w', padx = 5, pady = 20)
    text_ip.grid(row = 0, column = 1, sticky = 'w', padx = 5, pady = 20)
    if(sendSock == None):
        text_ip.focus()
    else:
        text_username.focus()
    text_code.grid(row = 2, column = 1, sticky = 'w', padx = 5, pady = 10)
    #确认按钮
    botton_confirm = Button(Win_Login, text = 'Confirm' ,command = Identification)
    botton_confirm.grid(row = 3, column = 1, sticky = 'n', padx = 10, pady = 10)
    Win_Login.bind('<Key-Return>',Identification)
    ProgressBar = Progressbar(Win_Login,  value = 0, orient = 'horizontal', length = 380, maximum = 10, mode = 'indeterminate')
    ProgressBar.grid(row = 4, column = 0, columnspan = 3, sticky = N)

def Signup():#注册用户
    def recover_root():
        root.attributes("-disabled", 0)
        Win_Signup.destroy()
        
    Win_Signup = Toplevel(height = 200, width = 400)
    Win_Signup.transient(master = root)#永远位于其父窗口之上，伴随父窗口消失而消失
    Win_Signup.title('Sign Up')
    Win_Signup.geometry('400x300+400+150')
    Win_Signup.maxsize(400, 300)
    Win_Signup.minsize(400, 300)
    root.attributes("-disabled", 1)
    Win_Signup.protocol(name = "WM_DELETE_WINDOW", func = recover_root)
    #实现注册的函数
    def Registration(event = None):
        try:
            global private_key
            global private_iv
            global usr_root_dir
            global server_rsa_pubkey
            global client_rsa_prikey
            global threadQueue
            HOST = text_ip.get().strip()
            if(sendSock == None and Is_Correct_IP(HOST) == False):
                messagebox.showinfo(title = 'Fail', message = 'Invalid IP Address')
                #Info2_Insert('Invalid IP Address\n')
                return False
            username = text_username.get()
            code = text_code.get()
            if(8 <= len(username) <= 15 and 8 <= len(code) <= 15 and not if_has_chinese(username) and not if_has_chinese(code)):
                 #首先进行连接尝试
                if(sendSock == None):
                    
                    thread = threading.Thread(target = Connect, args = (None, HOST))
                    thread.setDaemon(True)
                    thread.start()
                    ProgressBar.start()
                    while(1):
                        time.sleep(0.05)
                        root.update()
                        if(threadQueue.empty()):
                            continue
                        result = threadQueue.get()
                        print(result)
                        if(result[1] == Connect.__name__):
                            if(result[0] == False):
                                ProgressBar.stop()
                                messagebox.showinfo(title = 'Fail', message = 'Fail to connect to the server\nPlease try again')
                                Info1_Insert('Fail to connect to the server. Please try again\n')
                                
                                return False
                            else:break
                username_e = rsa.encrypt(username.encode('utf-8'), server_rsa_pubkey)#连接成功就已经得到了服务器的rsa公钥
                code_e = rsa.encrypt(code.encode('utf-8'),server_rsa_pubkey)
                Mode_e = rsa.encrypt('signup'.encode('utf-8'),server_rsa_pubkey)
                while(1):#密钥生成长度不稳定，可能是77+5=82，也可能是83，因此必须要稳定在82，反复生成。
                    (pub_key, pri_key) = rsa.newkeys(256)
                    pub_key_n, pub_key_e = str(pub_key.n).encode('utf-8'), str(pub_key.e).encode('utf-8')
                    filedata_size = len(pub_key_n + pub_key_e)
                    if(filedata_size != 82):
                        continue
                    else:
                        break
                #client_rsa_prikey = pri_key#临时解密返回结果，不需要保存客户端的rsa私钥
                DisableButton()
                message = struct.pack("32s32s32ssI2048s", Mode_e, username_e, code_e, '3'.encode('utf-8'), filedata_size, pub_key_n + pub_key_e)
                #发送数据块
                sendSock.settimeout(4)
                #sendSock.sendall(message)
                thread = threading.Thread(target = threadSendall, args = (sendSock, message))
                thread.setDaemon(True)
                thread.start()
                left_data_size = RECV_BUFSIZE
                total_data = b''
                while(left_data_size):
                    recv_data = sendSock.recv(left_data_size)
                    total_data += recv_data
                    recv_size = len(recv_data)
                    left_data_size -= recv_size
                print(len(total_data))
                data_size, rest_data = struct.unpack("I8188s", total_data)
                real_data = rest_data[:data_size]
                re_message = eval(real_data.decode('utf-8'))#得到加密后的验证结果、密钥和盐
                certificate = rsa.decrypt(re_message[0], pri_key).decode('utf-8')#这是个例外，只有注册的时候没有AES加密参与，全程rsa加密算法
                EnableButton()
                if(certificate == 'success'): 
                    Info2_Insert( 'New client: ' + username + ' signed up successfully!\n')
                    root.attributes("-disabled", 0)
                    Win_Signup.withdraw()
                    messagebox.showinfo(title = 'Success', message = 'User ' + username + ' Signed up')
                    #Info2_Insert('User ' + username + ' Signed up\n')
                elif(certificate == 'fail'):
                    messagebox.showinfo(title = 'Fail', message = 'This username has already existed')
                    #Info2_Insert('This username has already existed\n')
                elif(certificate == 'limit'):
                    messagebox.showinfo(title = 'Fail', message = 'The request has been refused for being\ntoo frequent. Please try it later')
                    #Info2_Insert('The request has been refused for being too frequent. Please try it later\n')
                if(sendSock != None):
                    sendSock.settimeout(None)
                Disconnect()
            else:
                messagebox.showinfo(title = 'Warning', message = 'Invalid username or password')
                #Info2_Insert('Invalid username or password\n')
                if(sendSock != None):
                    sendSock.settimeout(None)
                Disconnect()
        except Exception as e:
            traceback.print_exc()          
            EnableButton()
            if(sendSock != None):
                sendSock.settimeout(None)
            Disconnect()
            

   #提示label
    label_server_ip = Label(Win_Signup, text = 'Server IP', width = 15)
    label_server_ip.grid(row = 0, column = 0, sticky = 'w', padx = 10, pady = 20)
    label_username = Label(Win_Signup, text = 'Username', width = 15)
    label_username.grid(row = 1, column = 0, sticky = 'w', padx = 10, pady = 20)
    label_code = Label(Win_Signup, text = 'Code', width = 15)
    label_code.grid(row = 2, column = 0, sticky = 'w', padx = 10, pady = 20)
    #输入要求提示
    label_req1 = Label(Win_Signup, text = '8-15 characters' )
    label_req1.grid(row = 1, column = 2, sticky = 'w', padx = 10, pady = 20)
    label_req2 = Label(Win_Signup, text = '8-15 characters')
    label_req2.grid(row = 2, column = 2, sticky = 'w', padx = 10, pady = 20)
    #输入文本框
    text_ip = Entry(Win_Signup, width = 20)
    text_username = Entry(Win_Signup, width = 20)
    text_code = Entry(Win_Signup, width = 20, show = '*') 
    text_username.grid(row = 1, column = 1, sticky = 'w', padx = 5, pady = 20)
    text_ip.grid(row = 0, column = 1, sticky = 'w', padx = 5, pady = 20)
    if(sendSock == None):
        text_ip.focus()
    else:
        text_username.focus()
    text_code.grid(row = 2, column = 1, sticky = 'w', padx = 5, pady = 10)
    #确认按钮
    botton_confirm = Button(Win_Signup, text = 'Register' ,command = Registration)
    botton_confirm.grid(row = 3, column = 1, sticky = 'n', padx = 10, pady = 10)
    ProgressBar = Progressbar(Win_Signup,  value = 0, orient = 'horizontal', length = 380, maximum = 10, mode = 'indeterminate')
    ProgressBar.grid(row = 4, column = 0, columnspan = 3, sticky = N)
    Win_Signup.bind('<Key-Return>', Registration)
    

def get_realdir(client,server):#给客户文件名，服务器路径名，得到真正在服务器中文件存的位置
    server = server + '/'+ str(client.split('/')[-1])
    return server

def get_realdir_case(filecase, client, server):
    case_root = '/'.join(filecase.split('/')[:-1])
    root_len = len(case_root)
    return str(server + client[root_len:])

def file_list(rootDir): #遍历得到用户所选文件夹下所有文件
    filelist = []
    case = []
    for root, dirs, files in os.walk(rootDir):
        for file in files:
            filelist.append(root.replace('\\' ,'/')+'/'+ file)
        if(not os.listdir(root)):
            case.append(root.replace('\\', '/'))
    return str(filelist + case)

    
def send_single_file(sendSock, pr_processor, client_filename, server_filename, Mode, username_e, code_e):
    Mode_e = rsa.encrypt(Mode.encode('utf-8'), server_rsa_pubkey)#传输的Mode_e必须是rsa加密
    global threadQueue
    global RECV_BUFSIZE
    if(Mode == 'sendfile'):
        fresh_freq = 100
        file_total_size = os.path.getsize(client_filename)/fresh_freq#文件总大小，bytes单位,为了减少内层循环计算量，百分比计算提前等效运算
        file_read_size = 0                                #已传输文件大小
        counter = 0
        
        file_data_e = pr_processor.encrypt(server_filename.encode('utf-8'))
        filedata_size = len(file_data_e)#加密后大小
        message = struct.pack("32s32s32ssI2048s", Mode_e, username_e, code_e, '0'.encode('utf-8'), filedata_size, file_data_e)#把应存在服务器中的位置发送给服务器
        #发送数据块
        #print("info size is :", len(message))
        #sendSock.sendall(message)
        thread = threading.Thread(target = threadSendall, args = (sendSock, message))
        thread.setDaemon(True)
        thread.start()
        while(1):
            root.update()
            if(threadQueue.empty()):
                continue
            result = threadQueue.get()
            if(result[1] == threadSendall.__name__):
                if(result[0] == True):
                    break
        left_data_size = RECV_BUFSIZE
        total_data = b''
        while(left_data_size):
            recv_data = sendSock.recv(left_data_size)
            total_data += recv_data
            recv_size = len(recv_data)
            left_data_size -= recv_size
        data_size, rest_data = struct.unpack("I8188s", total_data)
        real_data = rest_data[:data_size]
        
        res = rsa.decrypt(eval(real_data.decode('utf-8'))[0], client_rsa_prikey).decode('utf-8')#接收文件是否冲突的信息
        if(res == 'exist'):
            messagebox.showinfo(title = 'Warning', message = 'The file has already existed in\nthe server directory')#无法send，令用户重新选择文件
            #Info1_Insert('The file has already existed in the server directory\n')
            return False
        elif(res == 'fail'):
            messagebox.showinfo(title = 'Warning', message = 'Please select a filecase, not a file')#无法send，令用户重新选择文件
            #Info1_Insert( 'Please select a filecase, not a file\n')
            return False
        else:
            fhead = struct.pack('128s11I',client_filename.encode('utf-8'),0,0,0,0,0,0,0,0,os.stat(client_filename).st_size,0,0)
            file_data_e = pr_processor.encrypt(fhead)
            filedata_size = len(file_data_e)
            message = struct.pack("32s32s32ssI2048s", Mode_e, username_e, code_e, '1'.encode('utf-8'), filedata_size, file_data_e)
            #print("head size is :", len(message))
            #sendSock.sendall(message)
            thread = threading.Thread(target = threadSendall, args = (sendSock, message))
            thread.setDaemon(True)
            thread.start()
            #res = pr_processor.decrypt(eval(sendSock.recv(1024).decode('utf-8'))[0]).decode('utf-8')#接收传输成功与否的信息，默认成功
            left_data_size = RECV_BUFSIZE
            total_data = b''
            while(left_data_size):
                recv_data = sendSock.recv(left_data_size)
                total_data += recv_data
                recv_size = len(recv_data)
                left_data_size -= recv_size
            
            data_size, rest_data = struct.unpack("I8188s", total_data)
            real_data = rest_data[:data_size]
            res = rsa.decrypt(eval(real_data.decode('utf-8'))[0], client_rsa_prikey).decode('utf-8')
            if(res == 'fail'): 
                Info1_Insert( 'The file transportation fails, Please send again' + '\n')
                return False
            else:
                try:
                    fp = codecs.open(client_filename,'rb')
                    label5['text'] = "0%"
                    while 1:
                        filedata = fp.read(BUFSIZE - 1)
                        if not filedata: 
                            break
                        file_read_size += len(filedata)#总共传输的有效数据大小bytes
                        counter += 1
                        file_data_e = pr_processor.encrypt(filedata)
                        filedata_size = len(file_data_e)
                        message = struct.pack("32s32s32ssI65536s", Mode_e, username_e, code_e, '2'.encode('utf-8'), filedata_size, file_data_e)
                        #print("filedata size is :", len(message))
                        thread = threading.Thread(target = threadSendall, args = (sendSock, message))
                        thread.setDaemon(True)
                        thread.start()
                        if(counter % 2 == 0):
                            percent = file_read_size / file_total_size
                            label5['text'] = str(int(percent))+"%"
                            ProgressBar['value'] = percent     
                        #res = pr_processor.decrypt(eval(sendSock.recv(4096).decode('utf-8'))[0]).decode('utf-8')#接收文件传输是否成功的信息
                        left_data_size = RECV_BUFSIZE
                        total_data = b''
                        while(left_data_size):
                            recv_data = sendSock.recv(left_data_size)
                            total_data += recv_data
                            recv_size = len(recv_data)
                            left_data_size -= recv_size
                       
                        data_size, rest_data = struct.unpack("I8188s", total_data)
                        real_data = rest_data[:data_size]
                        res = rsa.decrypt(eval(real_data.decode('utf-8'))[0], client_rsa_prikey).decode('utf-8')
                        if(res == 'fail'):   
                            Info1_Insert( 'The file transportation fails, Please send again' + '\n')
                            return False
                        else: root.update()
                    Info1_Insert( str(client_filename.split('/')[-1]) + ' has been sent to directory: ' + str(server_filename) + '\n' + "Size: " + '{:.3f}'.format(os.path.getsize(client_filename)/1024) + "Kb\n")
                    Info1_Insert( u"File transportation finished. Send more or disconnect\n")
                    fp.close()
                    label5['text'] = ''
                    ProgressBar['value'] = 0
                    return True
                except ConnectionAbortedError:
                    traceback.print_exc()
                    Info1_Insert('Connection error, please retry it'+'\n')
                    label5['text'] = ''
                    ProgressBar['value'] = 0
                    fp.close()
                    return False
    elif(Mode == 'senddir'):
        try:
            file_data_e = pr_processor.encrypt(server_filename.encode('utf-8'))
            filedata_size = len(file_data_e)#加密后大小
            message = struct.pack("32s32s32ssI2048s", Mode_e, username_e, code_e, '0'.encode('utf-8'), filedata_size, file_data_e)#把应存在服务器中的位置发送给服务器
            #发送数据块
            thread = threading.Thread(target = threadSendall, args = (sendSock, message))
            thread.setDaemon(True)
            thread.start()
            while(1):
                root.update()
                if(threadQueue.empty()):
                    continue
                result = threadQueue.get()
                if(result[1] == threadSendall.__name__):
                    if(result[0] == True):
                        break
            left_data_size = RECV_BUFSIZE
            total_data = b''
            while(left_data_size):
                recv_data = sendSock.recv(left_data_size)
                total_data += recv_data
                recv_size = len(recv_data)
                left_data_size -= recv_size     
            data_size, rest_data = struct.unpack("I8188s", total_data)
            real_data = rest_data[:data_size]
            res = rsa.decrypt(eval(real_data.decode('utf-8'))[0], client_rsa_prikey).decode('utf-8')
            if(res == 'exist'):
                messagebox.showinfo(title = 'Warning', message = server_filename + ' The file has already existed in\nthe server directory')#无法send，令用户重新选择文件
                #Info1_Insert(server_filename + ' The file has already existed in the server directory\n')
                return False
            elif(res == 'success'):
                Info1_Insert( str(client_filename) + ' has been created in directory: ' + str(server_filename) + '\n')
                Info1_Insert( u"Case transportation finished. Send more or disconnect\n")
                return True
        except Exception:
             traceback.print_exc()
             Info1_Insert('Transportation error, please retry it'+'\n')
             return False
# 客户端发送文件
def Client():
    try:
        pr_processor = encode_decode.prpcrypt(key = private_key, iv = private_iv)
        username = userlist.get()
        count= 1
        global sendSock
        if sendSock == None :#sendSock 还不存在的话说明没有建立连接
            Info1_Insert("Please enter the valid IP and click the 'Connect' Button to get connected with the server\n")
            return
        else:
            client_filename = Text_clientpath.get()
            if ((not os.path.isfile(client_filename)) and (not os.path.isdir(client_filename))):
                Info1_Insert( u"The client directory does not exist, please choose again\n")
                Text_clientpath.delete('0',END) #发现文件目录不存在清空文本框
                return  
            server_directory = Text_serverpath.get().strip()
            if(len(server_directory) == 0):# or '.' in server_directory.split('/')[-1]):#其实文件夹完全可以有.这个字符
                Info2_Insert( u"The server directory must be a filecase\n") 
                return
            username_e = pr_processor.encrypt(username.encode('utf-8'))
            code_e = pr_processor.encrypt('0'.encode('utf-8'))
            DisableButton()
            if(os.path.isfile(client_filename)):
                Mode = 'sendfile'
                server_filename = get_realdir(client = client_filename,server = server_directory)#得到拼接后的真正的服务器可写路径
                start = clock()
                if(send_single_file(sendSock, pr_processor, client_filename, server_filename, Mode, username_e, code_e)):
                    finish = clock()
                    time = finish - start
                    #print(start, finish, time)
                    Info1_Insert( "Time: %.2fs\n" % time )
                    insert_tree_node(Dir_Tree2, server_filename)    
            elif(os.path.isdir(client_filename)):
                filenamelist = eval(file_list(client_filename))#遍历得到所有子文件的完整目录列表
                root_filecase = get_realdir(client = client_filename, server = server_directory)#传递的根文件夹在服务器的路径，用于更新树
                fail_flag = 0
                start_all = clock()
                for filename in filenamelist:
                    if(os.path.isfile(filename)):
                        Mode = 'sendfile'
                    elif(os.path.isdir(filename)):
                        Mode = 'senddir'
                    server_filename = get_realdir_case(filecase = client_filename, client = filename, server = server_directory)
                    start = clock()
                    if(send_single_file(sendSock, pr_processor, filename, server_filename, Mode, username_e, code_e)):
                        finish = clock()
                        time = finish - start
                        Info1_Insert( "Time: %.2fs\n\n" % time )
                        insert_tree_node(Dir_Tree2, root_filecase)
                    else:
                        fail_flag = 1
                        Info1_Insert( "'" + filename + "'" + "failed to be transported to " + server_directory + "\n")
                        root.update()
                if(fail_flag == 0):
                    finish_all = clock()
                    time_all = finish_all - start_all
                    Info1_Insert( "'" + client_filename + "'" + "has been successfully transported to " + server_directory + "\n")
                    Info1_Insert( "Time: %.2fs\n\n" % time_all)
                    root.update()
                else:
                    finish_all = clock()
                    time_all = finish_all - start_all
                    Info1_Insert("Several files or filecases failed to be transported to " + server_directory + "\n")
                    Info1_Insert( "Total time: %.2fs\n\n" % time_all)
                    root.update()
            EnableButton()
    except Exception:
        traceback.print_exc()
        EnableButton()              
       

#断开连接
def Disconnect():
    global sendSock
    global private_key
    global private_iv
    global usr_root_dir
    global server_dir_hash
    if sendSock == None:#sendSock 还不存在的话说明没有建立连接   
        Info1_Insert("Please enter the valid IP and click the 'Connect' Button to get connected with the server\n")
        return
    else:   
        try:  
            username = userlist.get()
            username_e = processor.encrypt(username.encode('utf-8'))
            code_e = processor.encrypt('0'.encode('utf-8'))
            Mode_e = rsa.encrypt('disconnect'.encode('utf-8'), server_rsa_pubkey)
            
            message = struct.pack("32s32s32ssI2048s", Mode_e, username_e, code_e, '5'.encode('utf-8'), 0, processor.encrypt('0'.encode('utf-8')))
            sendSock.sendall(message)
        except (ConnectionResetError, ConnectionAbortedError):
            pass
        except Exception as e:
            traceback.print_exc()
            
        sendSock.close()
        DisableButton()
        Info2_Insert(u"Disconnected\n")
        userlist['state'] = NORMAL
        userlist.delete('0', END)
        userlist['state'] = DISABLED
        Text_serverpath['state'] = NORMAL
        Text_serverpath.delete('0', END)
        Text_serverpath['state'] = DISABLED
        server_dir_hash = {}#清空目录缓存hash
        usr_root_dir = ''#清空当前用户根目录
        label5['text'] = ''
        ProgressBar['value'] = 0
        root.update()
        private_key = ''
        private_iv = ''#全局密钥置空
        delete_tree(Dir_Tree2)
        filemenu.entryconfig(0, state = NORMAL)
        filemenu.entryconfig(1, state = NORMAL)
        filemenu.entryconfig(2, state = DISABLED)
        sendSock = None
        

def Logout():#用户登出功能
    def recover_root():
        root.attributes("-disabled", 0)
        Win_Logout.destroy()

    def user_logout():
        username = userlist.get() 
        Info2_Insert( 'Client '+ username + ' logged out.\n')
        userlist['state'] = NORMAL
        userlist.delete('0', END)
        userlist['state'] = DISABLED
        filemenu.entryconfig(0, state = 'normal')
        filemenu.entryconfig(2, state = 'disabled')
        global sendSock
        global private_key
        global private_iv
        global usr_root_dir
        global server_dir_hash
        private_key = ''
        private_iv = ''
        delete_tree(Dir_Tree2)
        server_dir_hash = {}#清空目录缓存hash
        usr_root_dir = ''#清空当前用户根目录
        label5['text'] = ''
        ProgressBar['value'] = 0
        try:
            Disconnect()
        except:
            pass
        DisableButton()
        if(sendSock):
            sendSock = None
        root.update()
        recover_root()
     
    Win_Logout = Toplevel(height = 200, width = 400)
    Win_Logout.transient(master = root)#永远位于其父窗口之上，伴随父窗口消失而消失
    Win_Logout.title('Sign Up')
    Win_Logout.geometry('250x150+500+250')
    Win_Logout.maxsize(250, 150)
    Win_Logout.minsize(250, 150)
    root.attributes("-disabled", 1)
    Win_Logout.protocol(name = "WM_DELETE_WINDOW", func = recover_root)
    #基础框架
    frm_up = Frame(Win_Logout, height = 75)
    frm_up.pack(side = TOP, anchor = W, fill = X)
    frm_down = Frame(Win_Logout, height = 75)
    frm_down.pack(side = TOP, anchor = W, fill = X)
    frm_up.propagate(FALSE)
    frm_down.propagate(FALSE)
    #提示label
    label_warning = Label(frm_up, text = 'Confirm to logged out?')
    label_warning.pack( side = LEFT, pady = 20, padx = 45)
    #确认和取消按钮
    botton_confirm = Button(frm_down, text = 'Confirm',command = user_logout, width = 8)
    botton_confirm.pack(side = LEFT,fill = 'x',pady = 15, padx = 30 )
    botton_cancel = Button(frm_down, text = 'Cancel',command = recover_root, width = 8)
    botton_cancel.pack(side = RIGHT,fill = 'x',pady = 15, padx = 30)
    Win_Logout.bind('<Key-Return>', user_logout)    

def ClearInfo1():
    Info1['state'] = NORMAL
    Info1.delete('0.0',END)
    Info1['state'] = DISABLED

def ClearInfo2():
    Info2['state'] = NORMAL
    Info2.delete('0.0',END)
    Info2['state'] = DISABLED
    
def IntoDir():
    pr_processor = encode_decode.prpcrypt(key = private_key, iv = private_iv)
    username = userlist.get()
    global sendSock
    global threadQueue
    try:
        if sendSock == None :#sendSock 还不存在的话说明没有建立连接  
            Info1_Insert("Please enter the valid IP and click the 'Connect' Button to get connected with the server\n")
            return
        else:
            server_directory = Text_serverpath.get().strip()
            if(len(server_directory) == 0): 
                Info2_Insert( u"The server directory can not be empty\n")
                return
            elif(len(server_directory) > 0 and (not server_directory in server_dir_hash)):
                #if(len(server_directory.split('/')[-1].split('.')) > 1):#点‘.’在linux中可以作为文件夹的名字，因此不能通过这个来判断是不是文件夹，只能交由server判断
                    #return
                DisableButton()
                username_e = pr_processor.encrypt(username.encode('utf-8'))
                code_e = pr_processor.encrypt('0'.encode('utf-8'))
                Mode_e = rsa.encrypt('intodir'.encode('utf-8'), server_rsa_pubkey)
                file_data_e = pr_processor.encrypt(server_directory.encode('utf-8'))
                filedata_size = len(file_data_e)#加密后大小
                message = struct.pack("32s32s32ssI2048s", Mode_e, username_e, code_e, '0'.encode('utf-8'), filedata_size, file_data_e)#把用户想查看的文件夹路径发送给服务器
                #发送数据块
                #sendSock.sendall(message)
                thread = threading.Thread(target = threadSendall, args = (sendSock, message))
                thread.setDaemon(True)
                thread.start()
                while(1):
                    root.update()
                    if(threadQueue.empty()):
                        continue
                    result = threadQueue.get()
                    if(result[1] == threadSendall.__name__):
                        if(result[0] == True):
                            break
                left_data_size = RECV_BUFSIZE
                total_data = b''
                while(left_data_size):
                    recv_data = sendSock.recv(left_data_size)
                    total_data += recv_data
                    recv_size = len(recv_data)
                    left_data_size -= recv_size
                data_size, rest_data = struct.unpack("I8188s", total_data)
                real_data = rest_data[:data_size]
                re_message = eval(real_data.decode('utf-8'))#得到加密后的返回结果
                certificate = rsa.decrypt(re_message[0], client_rsa_prikey).decode('utf-8')
                EnableButton()
                if(certificate == 'success'):
                    UserDir = pr_processor.decrypt(re_message[4]).decode('utf-8')
                    into_dir = eval(UserDir.replace('\\\\','/'))
                    delete_tree(Dir_Tree2)
                    build_tree(Dir_Tree2, into_dir)
                    server_dir_hash[into_dir[0]] = into_dir   
                    Info2_Insert( u'CWD:\n' + server_directory + '\n')
                    return
                elif(certificate == 'nonexist'):#只能说明此时这个文件夹在server已经被删除了         
                    Info2_Insert( u'This directory does not exist\n')
                    return
                elif(certificate == 'fail'):#说明是文件，无法into
                    return
            elif(len(server_directory) > 0 and server_directory in server_dir_hash):
                delete_tree(Dir_Tree2)
                build_tree(Dir_Tree2, server_dir_hash[server_directory])
                Dir_Tree2.see(Dir_Tree2.get_children()[0])
    except Exception as e:    
        EnableButton()
        root.update()
        
def BackDir():
    global server_dir_hash
    current_directory = Dir_Tree2.item(Dir_Tree2.get_children()[0], 'values')[0]
    if(current_directory == usr_root_dir):
        return
    back_directory_root = '/'.join(current_directory.split('/')[:-1])
    delete_tree(Dir_Tree2)
    build_tree(Dir_Tree2, server_dir_hash[back_directory_root])
    Text_serverpath['state'] = NORMAL
    Text_serverpath.delete('0', END)
    Text_serverpath.insert('end', Dir_Tree2.item(Dir_Tree2.get_children()[0], 'values')[0])
    Text_serverpath['state'] = DISABLED
    Info2_Insert( u'CWD:\n' + Dir_Tree2.item(Dir_Tree2.get_children()[0], 'values')[0] + '\n')
    return
def CreateCase():
    def recover_root():
        root.attributes("-disabled", 0)
        Win_Create.destroy()
        
    Win_Create = Toplevel(height = 200, width = 400)
    Win_Create.transient(master = root)#永远位于其父窗口之上，伴随父窗口消失而消失
    Win_Create.title('New Case Name')
    Win_Create.geometry('300x100+500+250')
    Win_Create.maxsize(300, 100)
    Win_Create.minsize(300, 100)
    root.attributes("-disabled", 1)
    Win_Create.protocol(name = "WM_DELETE_WINDOW", func = recover_root)
    #实现注册的函数
    def Create_New_Case(event = None):
        try:
            global sendSock
            pr_processor = encode_decode.prpcrypt(key = private_key, iv = private_iv)
            casename = case_name.get()
            username = userlist.get()
            casename_p = re.compile(r'(?!((^(con)$)|^(con)\..*|(^(prn)$)|^\..*|^\.\..*|^(prn)\..*|(^(aux)$)|^(aux)\..*|(^(nul)$)|^(nul)\..*|(^(com)[1-9]$)|^(com)[1-9]\..*|(^(lpt)[1-9]$)|^(lpt)[1-9]\..*)|^\s+|.*\s$)(^[^\\\/\:\*\\&?\"\<\>\|]{1,255}$)')
            if(casename_p.match(casename)):
                current_root = Dir_Tree2.item(Dir_Tree2.get_children()[0], "values")[0]#只能在当前目录树展示的目录下创建
                new_case_path = '/'.join([current_root, casename])
                #发送空文件夹，并创建
                Mode = 'senddir'
                username_e = processor.encrypt(username.encode('utf-8'))
                code_e = processor.encrypt('0'.encode('utf-8'))
                DisableButton()
                if(send_single_file(sendSock, pr_processor, new_case_path, new_case_path, Mode, username_e, code_e)):
                    messagebox.showinfo(title = 'Success', message = 'Create the new filecase successfully')
                    #Info1_Insert('Create the new filecase successfully\n')
                    insert_tree_node(Dir_Tree2, new_case_path)
                    EnableButton()
                    recover_root()
                else:
                    messagebox.showinfo(title = 'Fail', message = 'Fail to create the new filecase')
                    #Info1_Insert('Fail to create the new filecase\n')
                    EnableButton()
                    recover_root()
        except Exception as e:   
            sendSock.settimeout(None)
            EnableButton()

    case_name = Entry(Win_Create, width = 20)
    case_name.grid(row = 0, column = 0, sticky = W, padx = 20, pady = 25)
    case_name.focus()
    Confirm = Button(Win_Create, text = 'Confirm', width = 8, command = Create_New_Case)
    Confirm.grid(row = 0, column = 1, sticky = W, padx = 10, pady = 25)
    Win_Create.bind('<Key-Return>', Create_New_Case)
    
def Download(event = None):
    global threadQueue
    filename = Text_serverpath.get()
    client_directory = Text_clientpath.get()
    username = userlist.get()
    if(not os.path.isdir(client_directory)):      
        Info2_Insert( "Please choose a valid client directory.\n") 
        return
    pr_processor = encode_decode.prpcrypt(key = private_key, iv = private_iv)
    Mode_e = rsa.encrypt('download'.encode('utf-8'), server_rsa_pubkey)
    username_e = pr_processor.encrypt(username.encode('utf-8'))
    code_e = pr_processor.encrypt('0'.encode('utf-8'))
    file_data_e = pr_processor.encrypt(filename.encode('utf-8'))
    filedata_size = len(file_data_e)#加密后大小
    message = struct.pack("32s32s32ssI2048s", Mode_e, username_e, code_e, '0'.encode('utf-8'), filedata_size, file_data_e)#把用户想查看的文件夹路径发送给服务器
    #发送数据块
    #sendSock.sendall(message)
    thread = threading.Thread(target = threadSendall, args = (sendSock, message))
    thread.setDaemon(True)
    thread.start()
    while(1):
        root.update()
        if(threadQueue.empty()):
            continue
        result = threadQueue.get()
        if(result[1] == threadSendall.__name__):
            if(result[0] == True):
                break
          
    File_queue = set()#文件写入的本地路径由客户端自己计算，每次传输都要计算耗时很大，需要一个文件只计算一次，因此创建一个队列。
    server_directory = filename #下载的文件或文件夹在服务器的路径
    #接下来循环接收数据
    BUFSIZE = struct.calcsize("I70000s")
    counter = 0
    file_read_size = 0#为什么要在外面初始化？因为单个文件就是该文件已接收的大小，但是文件夹就必须是总接收大小，所以只能初始化一次，要拉到循环外面
    start = time.clock()
    sendSock.settimeout(5)
    while(1):
        left_data_size = BUFSIZE
        all_data = b''
        while(left_data_size):
            recv_data = sendSock.recv(left_data_size)
            #print(len(recv_data))
            all_data += recv_data
            left_data_size -=len(recv_data)
            #print(recv_data)
        try:
            data_size, re_message = struct.unpack("I70000s", all_data)
            Format = "%ds%dx" % (data_size, 70000 - data_size)
            re_message = struct.unpack(Format, re_message)[0]
            re_message = eval(re_message.decode('utf-8'))#得到加密后的返回结果,66000包括数据65535，验证32，文件名密文若干
        except Exception as e:
            traceback.print_exc()
            sendSock.settimeout(None)
            return
        certificate = rsa.decrypt(re_message[0], client_rsa_prikey).decode('utf-8')
        if(certificate == 'success'):
            filedata = pr_processor.decrypt(re_message[4])
            file_directory = pr_processor.decrypt(re_message[1]).decode('utf-8')#真正下载的文件在服务器的路径，若下载就是文件，那么和server_directory等价，但是不影响本地目录的计算
            if(file_directory not in File_queue):#说明这次数据来源于一个新文件，需要重新计算本地路径,并且接收其文件大小，方便计算进度条, 若下载的是文件夹，这个大小就是文件夹总大小，但是每一个新文件夹过来都要计算一次，有些冗余
                file_total_size = int(pr_processor.decrypt(re_message[2]).decode('utf-8'))/100#尽可能避免反复计算下文中算进度百分比时候需要的*100
                counter = 0
                client_filename = get_realdir_case(filecase = server_directory, client = file_directory, server = client_directory)#为了复用函数，变量之间有些等价交换，功能恰好可以复用
                #print(client_filename)
                File_queue.add(file_directory)#加入队列
                fileroot = '/'.join(client_filename.replace("//", "/").split('/')[:-1])
#得到本地路径的父路径，用于创建该文件所在文件夹
                if(not os.path.exists(fileroot)):
                    #print("make ",fileroot)
                    os.makedirs(fileroot)
            with open(client_filename, 'ab+') as fp:
                fp.write(filedata)
                file_read_size += len(filedata)#总共传输的有效数据大小bytes
                counter += 1
                if(counter % 20 == 0):
                    percent = file_read_size / file_total_size
                    label5['text'] = str(int(percent))+"%"
                    ProgressBar['value'] = percent
                    root.update()
                if(file_read_size >= file_total_size):
                    label5['text'] = ''
                    ProgressBar['value'] = 0
        elif(certificate == 'nonexist'):
            Info2_Insert( u'This directory does not exist\n')
            return
        elif(certificate == 'filecase'):#传回来一个空文件夹
            file_directory = pr_processor.decrypt(re_message[1]).decode('utf-8')
            client_filename = get_realdir_case(filecase = server_directory, client = file_directory, server = client_directory)
            os.makedirs(client_filename)
        elif(certificate == 'alldone'):#alldone最后一次接收数据可能是最后一个文件的最后一点数据，也可能是空文件夹，根据re_message[4]是否为空来判断
            filedata = pr_processor.decrypt(re_message[4])
            file_directory = pr_processor.decrypt(re_message[1]).decode('utf-8')
            if(len(filedata) == 0):#说明是空文件夹或者空文件
                client_filename = get_realdir_case(filecase = server_directory, client = file_directory, server = client_directory)
                try:
                    os.makedirs(client_filename)
                except FileExistsError:#这个是空文件，不是空文件夹。
                    with open(client_filename, "ab+") as fp:
                        pass
                    
            elif(len(filedata) >0):#来自文件数据，但是为了速度别忘了判断是不是新文件，如果文件很小，一次性传完，很可能就是新文件
                if(file_directory not in File_queue):#说明这次数据来源于一个新文件，需要重新计算本地路径
                    client_filename = get_realdir_case(filecase = server_directory, client = file_directory, server = client_directory)#为了复用函数，变量之间有些等价交换，功能恰好可以复用
                    File_queue.add(client_filename)#加入队列
                with open(client_filename, 'ab+') as fp:
                    fp.write(filedata)
            sendSock.setblocking(True)
            sendSock.settimeout(None)
            #最后一次传输后要清空下载队列
            File_queue = set()
            finish = time.clock()
            time_all =  finish - start
            Info2_Insert( server_directory + ' has been successfully downloaded to ' + client_directory + "\n")
            Info1_Insert( "Total time: %.2fs\n" % time_all )   
            return
        
def Execute():
    filename = Text_serverpath.get().strip()
    global sendSock
    global private_key
    global private_iv
    global threadQueue
    DisableButton()
    pr_processor = encode_decode.prpcrypt(key = private_key, iv = private_iv)
    Mode_e = rsa.encrypt('execute'.encode('utf-8'), server_rsa_pubkey)
    username = userlist.get()
    username_e = pr_processor.encrypt(username.encode('utf-8'))
    code_e = pr_processor.encrypt('0'.encode('utf-8'))
    file_data_e = pr_processor.encrypt(filename.encode('utf-8'))
    filedata_size = len(file_data_e)#加密后大小
    message = struct.pack("32s32s32ssI2048s", Mode_e, username_e, code_e, '0'.encode('utf-8'), filedata_size, file_data_e)#把用户想查看的文件夹路径发送给服务器
    #发送数据块
    #sendSock.sendall(message)
    thread = threading.Thread(target = threadSendall, args = (sendSock, message))
    thread.setDaemon(True)
    thread.start()
    while(1):
        root.update()
        if(threadQueue.empty()):
            continue
        result = threadQueue.get()
        if(result[1] == threadSendall.__name__):
            if(result[0] == True):
                break
    left_data_size = RECV_BUFSIZE
    total_data = b''
    while(left_data_size):
        recv_data = sendSock.recv(left_data_size)
        total_data += recv_data
        recv_size = len(recv_data)
        left_data_size -= recv_size
    data_size, rest_data = struct.unpack("I8188s", total_data)
    real_data = rest_data[:data_size]
    
    re_message = eval(real_data.decode('utf-8'))#得到加密后的返回结果
    certificate = rsa.decrypt(re_message[0], client_rsa_prikey).decode('utf-8')
    EnableButton()
    if(certificate == 'success'):
        Info2_Insert(filename + ' has been successfully added to the queue.\n')
        return True
    elif(certificate == 'nonexist'):
        Info2_Insert(filename + ' does not exist in the server directory.\n')
        return True
    elif(certificate == 'waiting'):
        Info2_Insert(filename + ' has already been in the queue. Please wait for execution.\n')
        return True
    elif(certificate == 'fail'):
        Info2_Insert(filename + ' can not be executed for a certain error.\n')
        return True

def Refresh():
    global sendSock
    global private_key
    global private_iv
    global usr_root_dir
    global server_dir_hash
    global threadQueue
    server_dir_hash = {}#清空目录缓存hash
    delete_tree(Dir_Tree2)
    pr_processor = encode_decode.prpcrypt(key = private_key, iv = private_iv)
    username = userlist.get()
    try:
        if sendSock == None :#sendSock 还不存在的话说明没有建立连接  
            Info1_Insert("Please enter the valid IP and click the 'Connect' Button to get connected with the server\n")
            return
        else:
            #if(len(server_directory.split('/')[-1].split('.')) > 1):#点‘.’在linux中可以作为文件夹的名字，因此不能通过这个来判断是不是文件夹，只能交由server判断
                #return
            DisableButton()
            username_e = pr_processor.encrypt(username.encode('utf-8'))
            code_e = pr_processor.encrypt('0'.encode('utf-8'))
            Mode_e = rsa.encrypt('refresh'.encode('utf-8'), server_rsa_pubkey)
            file_data_e = pr_processor.encrypt('0'.encode('utf-8'))
            filedata_size = len(file_data_e)#加密后大小
            message = struct.pack("32s32s32ssI2048s", Mode_e, username_e, code_e, '0'.encode('utf-8'), filedata_size, file_data_e)#把用户想查看的文件夹路径发送给服务器
            #发送数据块
            #sendSock.sendall(message)
            thread = threading.Thread(target = threadSendall, args = (sendSock, message))
            thread.setDaemon(True)
            thread.start()
            while(1):
                root.update()
                if(threadQueue.empty()):
                    continue
                result = threadQueue.get()
                if(result[1] == threadSendall.__name__):
                    if(result[0] == True):
                        break
            left_data_size = RECV_BUFSIZE
            total_data = b''
            while(left_data_size):
                recv_data = sendSock.recv(left_data_size)
                total_data += recv_data
                recv_size = len(recv_data)
                left_data_size -= recv_size
            data_size, rest_data = struct.unpack("I8188s", total_data)
            real_data = rest_data[:data_size]
            re_message = eval(real_data.decode('utf-8'))#得到加密后的返回结果
            certificate = rsa.decrypt(re_message[0], client_rsa_prikey).decode('utf-8')
            EnableButton()
            if(certificate == 'success'):
                UserDir = pr_processor.decrypt(re_message[4]).decode('utf-8')
                current_dir = eval(UserDir.replace('\\\\','/'))
                build_tree(Dir_Tree2, current_dir )#预先存入根目录
                usr_root_dir = current_dir[0]
                server_dir_hash[usr_root_dir] = current_dir   
                Info2_Insert( u'CWD:\n' + 'User root directory\n')
                return
            elif(certificate == 'nonexist'):#只能说明此时这个文件夹在server已经被删除了         
                Info2_Insert( u'This directory does not exist\n')
                return
            elif(certificate == 'fail'):
                return
            
    except Exception as e:    
        EnableButton()
        root.update()

def Pushing():
    try:
        global sendSock
        global private_key
        global private_iv
        global threadQueue
        if(not private_key ):
            #print("no link")
            return
        else:

            #DisableButton()
            pr_processor = encode_decode.prpcrypt(key = private_key, iv = private_iv)
            Mode_e = rsa.encrypt('pushing'.encode('utf-8'), server_rsa_pubkey)
            username = userlist.get()
            username_e = pr_processor.encrypt(username.encode('utf-8'))
            code_e = pr_processor.encrypt('0'.encode('utf-8'))
            file_data_e = pr_processor.encrypt('0'.encode('utf-8'))
            filedata_size = len(file_data_e)#加密后大小
            sendSock.settimeout(2.5)
            message = struct.pack("32s32s32ssI2048s", Mode_e, username_e, code_e, '0'.encode('utf-8'), filedata_size, file_data_e)#把用户轮询的请求发往server
            #发送数据块
            #sendSock.sendall(message)
            thread = threading.Thread(target = threadSendall, args = (sendSock, message))
            thread.setDaemon(True)
            thread.start()
            while(1):
                root.update()
                if(threadQueue.empty()):
                    continue
                result = threadQueue.get()
                if(result[1] == threadSendall.__name__):
                    if(result[0] == True):
                        break
            left_data_size = RECV_BUFSIZE
            total_data = b''
            while(left_data_size):
                recv_data = sendSock.recv(left_data_size)
                total_data += recv_data
                recv_size = len(recv_data)
                left_data_size -= recv_size
            data_size, rest_data = struct.unpack("I8188s", total_data)
            real_data = rest_data[:data_size]
            
            re_message = eval(real_data.decode('utf-8'))#得到加密后的返回结果
            certificate = rsa.decrypt(re_message[0], client_rsa_prikey).decode('utf-8')
            tasks_info = re_message[4]#包含任务管理信息的字典
            #EnableButton()
            if(certificate == 'success'):
                inqueue_tasks = pr_processor.decrypt(tasks_info['inqueue']).decode('utf-8')
                processing_tasks = pr_processor.decrypt(tasks_info['processing']).decode('utf-8')
                finished_tasks = pr_processor.decrypt(tasks_info['finished']).decode('utf-8')
                print(inqueue_tasks)
                print(processing_tasks)
                print(finished_tasks)
                return True
            elif(certificate == 'fail'):
                Info2_Insert('Notification error.\n')
                return True
    except socket.timeout:
        pass
    except:
        print('pushing error')
        #scheduler.shutdown(wait = False)
    

scheduler = BackgroundScheduler({
    'apscheduler.executors.default': {
        'class': 'apscheduler.executors.pool:ThreadPoolExecutor',
        'max_workers': '20'
    },
    'apscheduler.executors.processpool': {
        'type': 'processpool',
        'max_workers': '5'
    },
    'apscheduler.job_defaults.coalesce': 'false',
    'apscheduler.job_defaults.max_instances': '5',
    'apscheduler.timezone': 'UTC',
})
scheduler.add_job(Pushing, 'interval', seconds=3)
try:
    scheduler.start()
except:
    scheduler.shutdown(wait = False)

#浏览目录BrowserButton1
BrowserButton1=Button(frm_u1, text="File",command = CallFiles, width = 5 )
BrowserButton1.grid(row = 1, column = 3, pady = 10, padx =10,  sticky = W)
  
#浏览目录BrowserButton2
BrowserButton2=Button(frm_u1, text="Case", command = CallDir, width = 5  )
BrowserButton2.grid(row = 1, column = 4, pady = 10, sticky = W)

#Send按钮
SendButton=Button(frm_u1, text="Send", command = Client, width = 5)
SendButton['state'] = DISABLED
SendButton.grid(row = 1, column = 5, pady = 10,  padx = 10, sticky = W)

#Execute按钮
ExecuteButton=Button(frm_s1, text="Execute", command = Execute, width = 11)
ExecuteButton.grid(row = 0, column = 1, padx = 10, pady = 8, sticky = W)
ExecuteButton['state'] = DISABLED

#Download
DownloadButton = Button(frm_s1, text = 'Download', command = Download, width = 12)
DownloadButton.grid(row = 0, column = 2, sticky = W, pady = 10)
DownloadButton['state'] = DISABLED

#Refresh按钮
RefreshButton=Button(frm_s1, text="Refresh", command = Refresh, width = 7)
RefreshButton['state'] = DISABLED
RefreshButton.grid(row = 0, column = 3, pady = 8, padx = 5, sticky = W)

#New
NewButton = Button(frm_s1, text = 'New', command = CreateCase, width = 7)
NewButton.grid(row = 0, column = 4, sticky = W, padx = 5, pady = 10)
NewButton['state'] = DISABLED

#Back
BackButton=Button(frm_s1, text="Back",command = BackDir, width = 7)
BackButton.grid(row = 1, column = 3,  padx = 5, sticky = W, pady = 8)
BackButton['state'] = DISABLED

#Into
IntoButton=Button(frm_s1, text="Into",  command = IntoDir, width = 7)
IntoButton.grid(row = 1, column = 4, sticky = W, padx = 5,pady = 8)
IntoButton['state'] = DISABLED


#创建下拉菜单File，然后将其加入到顶级的菜单栏中
filemenu = Menu(menubar,tearoff=0)
filemenu.add_command(label="Log In", command=Login)
#filemenu.entryconfig(0, state = DISABLED)
filemenu.add_command(label="Sign Up", command=Signup)
#filemenu.entryconfig(1, state = DISABLED)
#filemenu.add_separator() #分割线
filemenu.add_command(label="Log Out", command=Logout)
filemenu.entryconfig(2, state = DISABLED)
menubar.add_cascade(label="User", menu=filemenu)
#创建另一个下拉菜单Edit
editmenu = Menu(menubar, tearoff=0)
editmenu.add_command(label="Clear User Info", command=ClearInfo1)
editmenu.add_command(label="Clear Server Info", command=ClearInfo2)
editmenu.add_command(label="Paste", command=Paste)
menubar.add_cascade(label="Edit",menu=editmenu)
#创建下拉菜单Help
helpmenu = Menu(menubar, tearoff=0)
helpmenu.add_command(label="About", command=about)
menubar.add_cascade(label="Help", menu=helpmenu)
#显示菜单
root.config(menu=menubar)
root.mainloop()
