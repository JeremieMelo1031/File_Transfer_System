#-*- encoding=UTF-8 -*-
from socket import *
import struct
import os
import encode_decode
import time
import binascii
from write_db import write_db
from server_certification import certification
from private_key_gene import private_key_gene
import select
from BFS_Dir import BFS_Dir
import rsa
from reg_limit import limit_ip
from exe_limit import exe_limit
import traceback
import logging
import multiprocessing
import hashlib
#事先生成
processor = encode_decode.prpcrypt(key = "qwerasdfzxcvqazx")
success = processor.encrypt('success'.encode('utf-8'))
fail = processor.encrypt('fail'.encode('utf-8'))
limit = processor.encrypt('limit'.encode('utf-8'))
nonexist = processor.encrypt('nonexist'.encode('utf-8'))
exist = processor.encrypt('exist'.encode('utf-8'))
nonexist = processor.encrypt('nonexist'.encode('utf-8'))
disconnect = processor.encrypt('disconnect'.encode('utf-8'))
sendfile = processor.encrypt('sendfile'.encode('utf-8'))
senddir = processor.encrypt('senddir'.encode('utf-8'))
intodir = processor.encrypt('intodir'.encode('utf-8'))
login = processor.encrypt('login'.encode('utf-8'))
signup = processor.encrypt('signup'.encode('utf-8'))
FILEINFO_SIZE = struct.calcsize('128s32sI8s')
RECV_BUFSIZE = struct.calcsize("32s32s32ssI2048s")
RECV_BUFSIZE2 = struct.calcsize("32s32s32ssI65536s")
def dir_list(Username): #遍历得到服务器文件目录列表
    print ("Please enter like this: /usr/local/bin")
    rootDir = '/usr/local'
    UserDir = rootDir + '/' + Username
    if(not os.path.exists(UserDir)):
        os.mkdir(UserDir)
        return str([UserDir])
    else:
        return str(BFS_Dir(UserDir))
        print(str(BFS_Dir(UserDir)))
            
def return_server_dir(connection):#向客户端返回服务器文件目录树
    dirlist = dir_list()
    connection.send(processor.encrypt(dirlist.encode('utf-8'))) #把客户端可见的服务器中的目录都发送给客户端
def file_list(rootDir): #遍历得到用户所选文件夹下所有文件,用于用户下载文件夹
    filelist = []
    case = []
    for root, dirs, files in os.walk(rootDir):
        for file in files:
            filelist.append(root.replace('\\' ,'/')+'/'+ file)
        if(not os.listdir(root)):
            case.append(root.replace('\\', '/'))
    return str(filelist + case)
    
def Receive_Data_To_File(connection, filename, pr_processor, BUFSIZE = 1024):#传输并写入文件数据，参数：连接的套接字，文件写入路径，私人密钥解码器，缓冲区大小（默认1024）
    Size = len(pr_processor.encrypt(b'\0'*(BUFSIZE - 1)))
    fp = open(filename,'wb')
    while 1:
        connection.settimeout(1)
        try:
            #time.sleep(0.1)
            filedata = connection.recv(Size)#带保护位的密文（2048）
            filedata_d = pr_processor.decrypt(filedata)#去除保护位的明文（1023）       
        except:
            fp.close()
            return
        if not filedata:
            fp.close()
            return
        fp.write(filedata_d)
        
def Receive_Dir(ep, fd, connection, message, pr_processor,  rsa_public_key, filedata_size, filedata_e, file_signal = None, BUFSIZE = 2048):#接受文件夹
    print("here")
    #pr_processor = encode_decode.prpcrypt(key = private_key_iv[0], iv = private_key_iv[1])#生成私人密钥的解码器
    print('there')
    Format = "%ds%dx" % (filedata_size, BUFSIZE - filedata_size)
    casename = pr_processor.decrypt(struct.unpack(Format, filedata_e)[0]).decode('utf-8')#[0]为了取Format中%ds的部分
    if(os.path.exists(casename)):
        message[0] = rsa.encrypt('exist'.encode('utf-8'), rsa_public_key)
        ep.modify(fd, select.EPOLLOUT)
     
    else:
        os.makedirs(casename)
        message[0] = rsa.encrypt('success'.encode('utf-8'), rsa_public_key)
        ep.modify(fd, select.EPOLLOUT)
        
def return_server_rsa_pubkey(connection, rsa_private_key):
    try:
        while(1):#密钥生成长度不稳定，可能是77+5=82，也可能是83，因此必须要稳定在82，反复生成。
            (pub_key, pri_key) = rsa.newkeys(256)
            rsa_private_key[connection.fileno()] = pri_key#存放服务器的rsa加密私钥
            pub_key_n, pub_key_e = str(pub_key.n).encode('utf-8'), str(pub_key.e).encode('utf-8')
            filedata_size = len(pub_key_n + pub_key_e)
            if(filedata_size != 82):
                continue
            else:
                break
        connection.sendall(pub_key_n + pub_key_e)
    except Exception as e:
        print("rsa_return error")
        
def Return_Into_Dir(ep, fd, connection, message, pr_processor, rsa_public_key,  filedata_size, filedata_e, file_signal = None, BUFSIZE = 2048):
    try:
        #pr_processor = encode_decode.prpcrypt(key = private_key_iv[0], iv = private_key_iv[1])#生成私人密钥的解码器
        Format = "%ds%dx" % (filedata_size, BUFSIZE - filedata_size)
        casename = pr_processor.decrypt(struct.unpack(Format, filedata_e)[0]).decode('utf-8')
        if(os.path.isdir(casename)):#这里要帮助客户端判断是不是文件夹，若是文件就根本不能进入下一级，要返回错误
            message[0] = rsa.encrypt('success'.encode('utf-8'), rsa_public_key)
            Into_Dir_e = pr_processor.encrypt(str(BFS_Dir(casename)).encode('utf-8'))
            message.append(Into_Dir_e)
            ep.modify(fd, select.EPOLLOUT)
            return
        elif(os.path.isfile(casename)):
            message[0] = rsa.encrypt('fail'.encode('utf-8'), rsa_public_key)
            ep.modify(fd, select.EPOLLOUT)
            return
        elif(not os.path.exists(casename)):
            message[0] = rsa.encrypt('nonexist'.encode('utf-8'), rsa_public_key)
            ep.modify(fd, select.EPOLLOUT)
            return
    except Exception as e:
        print(str(e) + "into error")
        return
        
def Receive_File(ep, fd, connection, message, pr_processor,  rsa_public_key, file_signal, filedata_size, filedata_e, BUFSIZE = 2048):#接受文件路径、头信息、数据并写入文件，参数：连接的套接字，私人密钥，传输缓冲区大小（默认1024）
    
    #pr_processor = encode_decode.prpcrypt(key = private_key_iv[0], iv = private_key_iv[1])#生成私人密钥的解码器

    file_signal = file_signal.decode('utf-8')
    if(file_signal == '0'):
        print("file_signal 0")
        print("len(message)", len(message))
        Format = "%ds%dx" % (filedata_size, BUFSIZE - filedata_size)
        filename = pr_processor.decrypt(struct.unpack(Format, filedata_e)[0]).decode('utf-8')
        if(os.path.exists(filename)):
            message[0] = rsa.encrypt('exist'.encode('utf-8'), rsa_public_key)#登录状态下所有的密文都用AES加密
            ep.modify(fd, select.EPOLLOUT)
        else:
            fileroot = '/'.join(filename.split('/')[:-1])
            if(os.path.isfile(fileroot)):
                
                message[0] = rsa.encrypt('fail'.encode('utf-8'), rsa_public_key)#登录状态下所有的密文都用AES加密
                ep.modify(fd, select.EPOLLOUT)
                return
            if(not os.path.exists(fileroot)):
                print("make ",fileroot)
                os.makedirs(fileroot)
            print(filename,"\nthe length of the filename:",len(filename),"bytes","\nthe type of the filename:",type(filename))
            message[3] = filename#扩展路径位，记录路径，无需加密
            #fp = open(filename, 'wb')#立即创建空文件，防止后续其他用户抢占同名文件。
            #fp.close()
            message[0] = rsa.encrypt('success'.encode('utf-8'), rsa_public_key)
            ep.modify(fd, select.EPOLLOUT)
            #connection.send(str(message[:3]).encode('utf-8'))
    elif(file_signal == '1'):
        try:
            Format = "%ds%dx" % (filedata_size, BUFSIZE - filedata_size)
            fhead = pr_processor.decrypt(struct.unpack(Format, filedata_e)[0])
            #fhead = connection.recv(FILEINFO_SIZE)#收文件头信息
            _,temp1,filesize,temp2 = struct.unpack('128s32sI8s',fhead)
            print("the size of the file is",filesize,"bytes")
            message[0] = rsa.encrypt('success'.encode('utf-8'), rsa_public_key )
            ep.modify(fd, select.EPOLLOUT)
            #connection.send(str(message[:3]).encode('utf-8'))
        except Exception as e:
            print(e)
            message[0] = rsa.encrypt('fail'.encode('utf-8'), rsa_public_key)
            os.remove(message[3])#若中途失败，则删除事先创建好的空文件，以免后续无法写入
            ep.modify(fd, select.EPOLLOUT)
            #connection.send(str(message[:3]).encode('utf-8'))
    elif(file_signal == '2'):
        try:
            BUFSIZE = 65536
            fp = open(message[3], 'ab+')#根据扩展位的路径写入，此时能保证文件是新创建的，不会override
            Format = "%ds%dx" % (filedata_size, BUFSIZE - filedata_size)
            filedata_e = struct.unpack(Format, filedata_e)[0]
            fp.write(pr_processor.decrypt(filedata_e))
            fp.close()
            message[0] = rsa.encrypt('success'.encode('utf-8'),  rsa_public_key)
            ep.modify(fd, select.EPOLLOUT)
        except Exception as e:
            print(e)
            message[0] = rsa.encrypt('fail'.encode('utf-8'),  rsa_public_key)
            os.remove(message[3])#若中途失败，则删除事先创建好的空文件，以免后续无法写入
            ep.modify(fd, select.EPOLLOUT)
            #connection.send(str(message[:2]).encode('utf-8'))
        #print ("File received")
        #connection.settimeout(None)
    #return True
            
def Download_File(ep, fd, connection, message, pr_processor,  rsa_public_key, filepointer, BUFSIZE = 32767):
    filename = filepointer[0][0]
    offset = filepointer[0][1]
    with open(filename, 'rb') as fp:
        fp.seek(offset)#设置读取文件游标的offset
        filedata = fp.read(BUFSIZE - 1)
        filepointer[0][1] = fp.tell()#读完之后将游标更新
        #print("fp", filepointer[0][1])
        #print("size", os.stat(filename).st_size)
        #print("queue", filepointer)
        if(filepointer[0][1] == os.stat(filename).st_size):#说明此次为该文件最后一次读取,此时应该将该文件从队列中删掉
            del filepointer[0]
        filedata_e = pr_processor.encrypt(filedata)
        message[0] = rsa.encrypt('success'.encode('utf-8'), rsa_public_key)
        message[1] = pr_processor.encrypt(filename.encode('utf-8'))#占用private_key的位置，用于告知用户正在发送的是什么文件，因为可能是文件夹下遍历得到的文件，用户可能并不知道
        message[4] = filedata_e#数据放在与之前Dir一样的第五个元素处，第六个元素要保持'download'
        ep.modify(fd, select.EPOLLOUT)
        
def execute_command(ep, fd, connection, message, pr_processor, filedata_size, casename, Username):
    #Format = "%ds%dx" % (filedata_size, BUFSIZE - filedata_size)
    #casename = pr_processor.decrypt(struct.unpack(Format, filedata_e)[0]).decode('utf-8')
    #Username = processor.decrypt(Username_e).decode('utf-8')
    Database = '/usr/local/' + Username + '/' + Username + '_exe.db'
    command_line = 'cat ' + casename
    os.system(command_line)   #执行文件
    exe_info = casename + ' executed.'
    print(exe_info)
    logging.info(exe_info)    #执行完毕后记录执行信息
    exe_limit(casename, Database, pid = 1)
    print("delete limit")
	
def ExecuteFile(ep, fd, connection, message, pr_processor, rsa_public_key, filedata_size, filedata_e, Username_e, BUFSIZE = 2048):
    try:
        Format = "%ds%dx" % (filedata_size, BUFSIZE - filedata_size)
        casename = pr_processor.decrypt(struct.unpack(Format, filedata_e)[0]).decode('utf-8')
        Username = pr_processor.decrypt(Username_e).decode('utf-8')
        Database = '/usr/local/' + Username + '/' + Username + '_exe.db'
        if(not exe_limit(casename, Database, pid = 0)):
            message[0] = rsa.encrypt('waiting'.encode('utf-8'), rsa_public_key)
            ep.modify(fd, select.EPOLLOUT)
            return
        logging.basicConfig(level = logging.DEBUG,
                format = '%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',   #字符串形式的当前时间 调用日志输出函数的模块的文件名 调用日志输出函数的语句所在的代码行 文本形式的日志级别 用户输出的消息
                datefmt = '%a, %d %b %Y %H:%M:%S',  #指定日期时间格式
                filename = '/usr/local/' + Username + '/' + Username + '.log',  #日志名
                filemode = 'w')
        if(os.path.isfile(casename)):   #如果文件存在，则执行
            exe_info = casename + ' in queue.'
            logging.info(exe_info)
            print(exe_info)
            
            p = multiprocessing.Process(target = execute_command, args = (ep, fd, connection, message, pr_processor, filedata_size, casename, Username))   #新建单一进程
            p.start()
            #p.join()		
            message[0] = rsa.encrypt('success'.encode('utf-8'), rsa_public_key)
            ep.modify(fd, select.EPOLLOUT)
        else:
            message[0] = rsa.encrypt('fail'.encode('utf-8'), rsa_public_key)
            ep.modify(fd, select.EPOLLOUT)
    except Exception as inst:
        print(str(inst))
        traceback.print_exc()
        message[0] = rsa.encrypt('fail'.encode('utf-8'), rsa_public_key)
        ep.modify(fd, select.EPOLLOUT)     
    
    
def CheckPushing(ep, fd, connection, message, pr_processor, rsa_public_key, filedata_size, filedata_e, Username_e, LogMD5, BUFSIZE = 2048):
    try:
        Username = pr_processor.decrypt(Username_e).decode('utf-8')
        with open('/usr/local/' + Username + '/' + Username + '.log', 'rb')as fp:
            Logdata = fp.read()
            m = hashlib.md5()   
            m.update(Logdata)
            MD5 = m.hexdigest()
            print(LogMD5[fd], MD5, type(MD5))
            if(LogMD5[fd] == MD5):
                message[0] = rsa.encrypt('still'.encode('utf-8'), rsa_public_key)
                ep.modify(fd, select.EPOLLOUT)
            else:
                message[0] = rsa.encrypt('changed'.encode('utf-8'), rsa_public_key)
                LogMD5[fd] = MD5
                with open('/usr/local/' + Username + '/' + Username + '_md5.txt', 'wb') as fh:
                    fh.write(MD5.encode('utf-8'))
                ep.modify(fd, select.EPOLLOUT)
    except:
        traceback.print_exc()
        message[0] = rsa.encrypt('fail'.encode('utf-8'), rsa_public_key)
        ep.modify(fd, select.EPOLLOUT)


    
def server():
    
    #侦听准备
    host= ''#input("input the server's IP address: ")
    port_list = [8090, 8120, 10520, 20520, 30520]
    port = 8090
    recvSock = socket(AF_INET,SOCK_STREAM)
    recvSock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)#设置IP地址 复用
    for port in port_list:
        try:
            recvSock.bind((host,port))
        except Exception as e:
            print(e, port,'is occupied')
        else:
            break
    else:
        print('no port is free')
        time.sleep(5)
        return
    fdmap = {recvSock.fileno():recvSock}
    recvSock.listen(5)
    recvSock.setblocking(False)#服务器设置非阻塞
    timeout = 10
    ep = select.epoll()
    ep.register(recvSock.fileno(), select.EPOLLIN)
    message = {}
    private_aes_processor = {}
    rsa_private_key = {}#存放服务器rsa私钥
    rsa_public_key = {}#存放客户端rsa公钥
    require = {}
    ipmap = {}
    LogMD5 = {}
    filepointer = {}#客户待下载文件队列（存放所有文件的文件路径及其当前文件读取游标：[filename， offset]）
    #侦听到请求后等待连接
    while(1):
        #time.sleep(0.2)
        events = ep.poll(timeout)
        if not events:
            continue

        
        for fd, event in events:
            connection = fdmap[fd]
            #如果活动connection等于recvSock，表示有新连接
            if connection == recvSock:
                new_connection, addr = recvSock.accept()
                print ("Client connected—> ", addr)
                ipmap[new_connection.fileno()] = addr[0]#把文件句柄对应的IP地址储存下来
                new_connection.setblocking(False)
                ep.register(new_connection.fileno(), select.EPOLLIN)
                fdmap[new_connection.fileno()] = new_connection
                require[new_connection.fileno()] = b''
                return_server_rsa_pubkey(new_connection, rsa_private_key)
            #检测到断连事件
            elif event & select.EPOLLHUP:
                print("client close")
                ep.unregister(fd)
                fdmap[fd].close()
                del fdmap[fd]
                del message[fd]
                del private_aes_processor[fd]
                del ipmap[fd]
                del LogMD5[fd]
            #可读事件
            elif event & select.EPOLLIN:

                #发送完目录后等待后续请求，进行常规单次收发处理
                Username_e = ''#初始化
                #is_disconnected_flag = 0
                #print("Waiting for Logging in or Signing up")          
                require[fd] = fdmap[fd].recv(RECV_BUFSIZE2)
                length = len(require[fd])
                if(RECV_BUFSIZE < length < RECV_BUFSIZE2):
                    #print('can not receive enough size of data, the size is :', length)
                    #ep.modify(fd, select.EPOLLIN)
                    left_data_size = RECV_BUFSIZE2 - length
                    
                    while(1):
                        try:
                            fdmap[fd].setblocking(True)
                            recv_data = fdmap[fd].recv(left_data_size)
                            require[fd] += recv_data
                            left_data_size -= len(recv_data)
                            #print(left_data_size, ' ', len(recv_data))
                            if(left_data_size == 0):
                                break
                        except BlockingIOError as inst:
                            print("EAGAIN_ALLDONE")
                            continue                     
                
                if(len(require[fd]) == RECV_BUFSIZE):
                    
                    Mode_e, Username_e, Code_e, file_signal, filedata_size, filedata_e  = struct.unpack("32s32s32ssI2048s",require[fd])
                else:
                    
                    Mode_e, Username_e, Code_e, file_signal, filedata_size, filedata_e  = struct.unpack("32s32s32ssI65536s",require[fd])
                require[fd] = b''
                Mode = rsa.decrypt(Mode_e, rsa_private_key[fd]).decode('utf-8')#注意在这里的mode必须用rsa来解密，意味着全程Mode都只能是rsa加密算法
                #print("Mode is ",Mode)
                
                #Username = rsa.decrypt(Username_e, rsa_private_key[fd]).decode('utf-8')
                if(Mode == 'disconnect'):#客户端主动断开连接
                    fdmap[fd].close()
                    del fdmap[fd]
                    del message[fd]
                    if(fd in private_aes_processor):
                        del private_aes_processor[fd]
                    del ipmap[fd]
                    print("Disconnected")
                    #is_disconnected_flag = 1
                    break

                if(Mode == 'login'):
                    print("登录模式")
                    Format = "%ds%ds%dx" % (77,5,1966)
                    pub_key_n, pub_key_e = struct.unpack(Format, filedata_e)
                    client_public_key = rsa.PublicKey(int(pub_key_n), int(pub_key_e))
                    Username = rsa.decrypt(Username_e, rsa_private_key[fd])
                    Code = rsa.decrypt(Code_e, rsa_private_key[fd])
                    cert_res = certification(processor.encrypt(Username), processor.encrypt(Code))#储存在数据库的不能是明文，必须是密文；但不能是客户端直接传过来的rsa密文，应该是服务器固定的AES加密密文，否则不能验证
                    if(cert_res == 'nonexist'):
                        message[fd] = [rsa.encrypt('nonexist'.encode('utf-8'), client_public_key), '', '', '']#这里也是例外，因为没有登陆成功，没有AES密钥生成，只能rsa加密
                        #fdmap[fd].send(str(message[Username_e]).encode('utf-8'))
                        ep.modify(fd, select.EPOLLOUT)
                    elif(cert_res == 'success'):
                        #验证成功后生成私钥并返回验证结果
                        rsa_public_key[fd] = client_public_key#只有验证成功才有要必要保存该次登录的客户端rsa公钥

                        print("The client: %s is logged in" % Username.decode('utf-8'))#利用已保存的服务器rsa私钥解密
                        private_key, private_iv = private_key_gene(Username_e)#使用rsa加密的用户名生成AESkey几乎没有重复风险
                        pr_processor = encode_decode.prpcrypt(key = private_key, iv = private_iv)#生成AES解码器
                        private_aes_processor[fd] = pr_processor#无需储存AESkey和iv，直接储存AES加密器更节省时间和空间。
                        private_key_rsa = rsa.encrypt(private_key.encode('utf-8'), rsa_public_key[fd])
                        private_iv_rsa = rsa.encrypt(private_iv.encode('utf-8'), rsa_public_key[fd])
                        #print(private_key_rsa,private_iv_rsa,type(private_key_rsa))
                        UserDir = dir_list(Username.decode('utf-8'))
                        UserDir_e = pr_processor.encrypt(UserDir.encode('utf-8'))#为了保证速度，对大型数据只能用AES加密，但因为随着AES密钥一起返回，所以客户端完全可以使用AES解密
                        message[fd] = [rsa.encrypt('success'.encode('utf-8'), rsa_public_key[fd]), private_key_rsa, private_iv_rsa, '', UserDir_e]#注意，此时success信号只能用rsa加密，因为客户端先判断是否认证成功才获取AES密钥，所以此处决不能使用AES加密
                        #private_key_iv = struct.pack("16s16s", private_key.encode('utf-8'), private_iv.encode('utf-8'))
                        #发送加密后结果、密钥和盐
                        #fdmap[fd].send(str(message[Username_e]).encode('utf-8'))
                        #检测用户日志及其MD5存在与否
                        Log_dir = '/usr/local/' + Username.decode('utf-8') + '/' + Username.decode('utf-8') + '.log'
                        LogMD5_dir = '/usr/local/' + Username.decode('utf-8') + '/' + Username.decode('utf-8') + '_md5.txt'
                        if(not os.path.isfile(Log_dir)):
                            os.makedirs(Log_dir)
                        else:pass
                        if(not os.path.isfile(LogMD5_dir)):
                            os.system('touch ' + LogMD5_dir)
                            with open(LogMD5_dir, 'wb') as fh:
                                m = hashlib.md5()
                                m.update('0'.encode('utf-8'))
                                fh.write(m.hexdigest().encode('utf-8'))
                        else:#若存在MD5应该读取MD5到LogMD5字典中
                            with open(LogMD5_dir, 'rb') as fh:
                                LogMD5[fd] = fh.read().decode('utf-8')
                        
                        ep.modify(fd, select.EPOLLOUT)
                        print("The result, private key and iv are sent to the client: %s" % Username.decode('utf-8'))
                        continue
                    else:
                        message[fd] = [rsa.encrypt('fail'.encode('utf-8'), client_public_key), '', '', '']
                        #fdmap[fd].send(str(message[Username_e]).encode('utf-8'))
                        ep.modify(fd, select.EPOLLOUT)
                elif(Mode == 'signup'):#注册模式
                    print("注册模式")
                    now = time.time()
                    Format = "%ds%ds%dx" % (77,5,1966)
                    pub_key_n, pub_key_e = struct.unpack(Format, filedata_e)
                    client_public_key = rsa.PublicKey(int(pub_key_n), int(pub_key_e))
                    if(limit_ip(ipmap[fd], now)):#先判断ip有没有被限制
                        message[fd] = [rsa.encrypt('limit'.encode('utf-8'), client_public_key), '', '', '']#这时候只有客户端的rsa公钥，只能使用rsa加密，这是个例外
                        ep.modify(fd, select.EPOLLOUT)
                        print("is limited")
                    else:
                        Username = rsa.decrypt(Username_e, rsa_private_key[fd])
                        Code = rsa.decrypt(Code_e, rsa_private_key[fd])
                        print("no limit")
                        sign = write_db(ipmap[fd], processor.encrypt(Username), processor.encrypt(Code))#经过服务器AES加密的用户信息才能写入数据库
                        if(sign == True):
                            message[fd] = [rsa.encrypt('success'.encode('utf-8'), client_public_key), '', '', '']
                            ep.modify(fd, select.EPOLLOUT)
                        else:
                            message[fd] = [rsa.encrypt('fail'.encode('utf-8'), client_public_key), '', '', '']
                            ep.modify(fd, select.EPOLLOUT)

                elif(Mode == 'sendfile'):#等待接收文件（路径、头信息、数据）
                    Receive_File(ep, fd, fdmap[fd], message[fd], private_aes_processor[fd],  rsa_public_key[fd], file_signal, filedata_size, filedata_e)
                elif(Mode == 'senddir'):#等待接受空文件夹
                    Receive_Dir(ep, fd, fdmap[fd], message[fd], private_aes_processor[fd],  rsa_public_key[fd], filedata_size, filedata_e)
                elif(Mode == 'intodir'):
                    Return_Into_Dir(ep, fd, fdmap[fd], message[fd], private_aes_processor[fd], rsa_public_key[fd], filedata_size, filedata_e)
                elif(Mode == 'refresh'):
                    Username = private_aes_processor[fd].decrypt(Username_e)
                    UserDir = dir_list(Username.decode('utf-8'))
                    UserDir_e = private_aes_processor[fd].encrypt(UserDir.encode('utf-8'))#为了保证速度，对大型数据只能用AES加密，但因为随着AES密钥一起返回，所以客户端完全可以使用AES解密
                    message[fd] = [rsa.encrypt('success'.encode('utf-8'), rsa_public_key[fd]), '', '', '', UserDir_e]
                    ep.modify(fd, select.EPOLLOUT)
                elif(Mode == 'download'):
                    Format = "%ds%dx" %(filedata_size, 2048 - filedata_size)
                    filename = private_aes_processor[fd].decrypt(struct.unpack(Format, filedata_e)[0]).decode('utf-8')#解密出客户想要下载的文件\目录完整路径
                    if(not os.path.exists(filename)):
                        message[fd] = [rsa.encrypt('nonexist'.encode('utf-8'), rsa_public_key[fd]), '', '', '']
                        ep.modify(fd, select.EPOLLOUT)
                    elif(os.path.isfile(filename)):#用户此次下载的只是个文件
                        file_size = private_aes_processor[fd].encrypt(str(os.stat(filename).st_size).encode('utf-8'))
                        message[fd] = [rsa.encrypt('exist'.encode('utf-8'), rsa_public_key[fd]),'', file_size, '', '', 'download']#引入第六个元素，来供EPOLLOUT来判断是否是下载。
                        filepointer[fd] = [[filename, 0]]#传输列表中加入这个文件及其初始化游标
                        ep.modify(fd, select.EPOLLOUT)
                    elif(os.path.isdir(filename)):#用户此次下载的是一个文件夹
                        filepointer[fd] = []
                        case_size = 0
                        filenamelist = eval(file_list(filename))#遍历得到所有子文件的完整目录列表
                        for file_name in filenamelist:
                           filepointer[fd].append([file_name, 0])#传输列表中加入这个文件及其初始化游标
                           case_size += int(os.stat(file_name).st_size)#这里只能是文件夹总大小
                        case_size = private_aes_processor[fd].encrypt(str(case_size).encode('utf-8'))
                        message[fd] = [rsa.encrypt('exist'.encode('utf-8'), rsa_public_key[fd]),'', case_size, '', '', 'download']#引入第六个元素，来供EPOLLOUT来判断是否是下载。
                        ep.modify(fd, select.EPOLLOUT)
                elif(Mode == 'execute'):
                    ExecuteFile(ep, fd, fdmap[fd], message[fd], private_aes_processor[fd], rsa_public_key[fd], filedata_size, filedata_e, Username_e)
                elif(Mode == 'pushing'):
                    CheckPushing(ep, fd, fdmap[fd], message[fd], private_aes_processor[fd], rsa_public_key[fd], filedata_size, filedata_e, Username_e, LogMD5)    
            #检测到可写事件
            elif event & select.EPOLLOUT:
                try:
                    if(len(message[fd]) <= 5):
                        
                        Format = "I%ds" % 8188
                        send_data = str(message[fd]).encode('utf-8')
                        data_size = len(send_data)
                        #print("data_size is ", data_size)
                        send_stream = struct.pack(Format,data_size, send_data)
                        fdmap[fd].sendall(send_stream)
                        if(len(message[fd]) == 5):
                            print( "Sending the database directory to the client")
                            del message[fd][4]
                        ep.modify(fd, select.EPOLLIN)
                    elif(len(message[fd]) == 6 and message[fd][5] == 'download'):
                        if(not filepointer[fd]):#下载队列已经为空，但是别忘了，message的第五个元素可能是最后一个文件读取的最后一次数据，也可能为空（当最后一次传输的是空文件夹时）
                            message[fd][0] = rsa.encrypt('alldone'.encode('utf-8'), rsa_public_key[fd])
                            while(1):
                                try:
                                    fdmap[fd].setblocking(True)
                                    send_data = str(message[fd]).encode('utf-8')
                                    data_size = len(send_data)
                                    Format = "I%ds" % 70000
                                    send_stream = struct.pack(Format, data_size, send_data)
                                    send_size = fdmap[fd].sendall(send_stream)
                                    #fdmap[fd].send(str(message[fd]).encode('utf-8'))#客户端完全可以根据message[4]是不是空来判断此次是文件数据还是空文件夹。
                                except BlockingIOError as inst:
                                    print("EAGAIN_ALLDONE")
                                    continue
                                else:break
                            print("alldone")
                            del message[fd][5]
                            del message[fd][4]                             
                            ep.modify(fd, select.EPOLLIN)#把此次connection重新添加到可读事件中
                        else:#传输队列依旧有文件  
                            filename = filepointer[fd][0][0]
                            if(os.path.isfile(filename)):
                                Download_File(ep, fd, fdmap[fd], message[fd], private_aes_processor[fd], rsa_public_key[fd], filepointer[fd])
                                while(1):
                                    try:
                                        fdmap[fd].setblocking(True)
                                        send_data = str(message[fd]).encode('utf-8')
                                        data_size = len(send_data)
                                        Format = "I%ds" % 70000
                                        send_stream = struct.pack(Format, data_size, send_data)
                                        send_size = fdmap[fd].sendall(send_stream)
                                    except BlockingIOError as inst:
                                        print("EAGAIN")
                                        fdmap[fd].setblocking(False)
                                        continue
                                    else:
                                        fdmap[fd].setblocking(False)
                                        #time.sleep(0.1)
                                        break
                                #print("sendsize",send_size)
                                
                                ep.modify(fd, select.EPOLLOUT)#保持可写事件
                                #此时依然是可写事件EPOLLOUT
                            elif(os.path.isdir(filename)):#此时对应文件夹下的空文件夹，注意这个空文件夹可能是队列最后一个待传输项！要有相应的处理
                                message[fd][0] = rsa.encrypt('filecase'.encode('utf-8'), rsa_public_key[fd])#提示客户端，这个是空文件夹，需要创建即可。
                                message[fd][1] = private_aes_processor[fd].encrypt("filename".encode('utf-8'))
                                message[fd][4] = ''#空文件夹不应该有数据，只有路径，这里是客户端判定最后一次alldone时接受的数据到底是文件夹还是文件的判据
                                #fdmap[fd].sendall(str(message[fd]).encode('utf-8'))
                                del filepointer[fd][0]#移出传输队列
                                ep.modify(fd, select.EPOLLOUT)#保持可写事件
                                
                                
                    
                except BlockingIOError as inst:
                    print("EAGAIN")
                    pass
                    
                except Exception as e:
                    print("写事件失败")
                    print(e)
                    traceback.print_exc()
            else:
                print("nothing", event)
    ep.unregister(recvSock.fileno())
    ep.close()
    recvSock.close()
        


if __name__ == "__main__":
    while(1):
        try:
            server()
        except Exception as e:
            traceback.print_exc()
            print(e, "total error")
            continue
             
