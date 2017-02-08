import os
def BFS_Dir(path, dirCallback = None, fileCallback = None):  
    queue = []  
    ret = []
    if(path.endswith("/")):
        path = path[:-1]
    queue.append(path);  
    while len(queue) > 0:  
        tmp = queue.pop(0)  
        if(os.path.isdir(tmp)):  
            ret.append(tmp)  
            for item in os.listdir(tmp):  
                queue.append(os.path.join(tmp, item))  
            if dirCallback:  
                dirCallback(tmp)  
        elif(os.path.isfile(tmp)):  
            ret.append(tmp)  
            if fileCallback:  
                fileCallback(tmp)
    length = len(path.split('/'))
    length2 = len(path) + 1
    return [path] + [i for i in ret if len(i.split('/')) == (length + 1)]
if __name__ == '__main__':
    print(BFS_Dir(u'/usr/local'))
    print(len(BFS_Dir(u'usr/local')))
