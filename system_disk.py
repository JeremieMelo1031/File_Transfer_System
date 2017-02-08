import ctypes
import os
 
def system_disk():
    sys=['/']
    lpBuffer = ctypes.create_string_buffer(78)
    ctypes.windll.kernel32.GetLogicalDriveStringsA(ctypes.sizeof(lpBuffer), lpBuffer)
    vol = lpBuffer.raw.split(b'\x00')        
    #遍历字母A到Z，忽略光驱的盘符
    for i in range(65,91):
        vol = chr(i) + ':'
        if os.path.isdir(vol):
            sys.append(vol)
    return sys
if __name__ == '__main__':
    print(system_disk())
