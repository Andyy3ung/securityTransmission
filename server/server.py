# server

import socket
import os
import hashlib
import rsa
from pyDes import des, CBC, PAD_PKCS5
import binascii
import random
import string

def des_encrypt(s,KEY):
    secret_key = KEY
    iv = secret_key
    k = des(secret_key, CBC, iv, pad=None, padmode=PAD_PKCS5)
    en = k.encrypt(s, padmode=PAD_PKCS5)
    return binascii.b2a_hex(en)

#生成8位随机密钥
def genrateKey():
    ran_str = ''.join(random.sample(string.ascii_letters + string.digits, 8))
    return ran_str

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server.bind(("localhost", 9999)) # 绑定监听端口

server.listen(5)  # 监听

print("监听开始..")

if os.path.isfile('serverpublic.pem'):  # 判断文件存在
    pass
else:
    # 先生成一对密钥，然后保存.pem格式文件，当然也可以直接使用
    (pubkey, privkey) = rsa.newkeys(1024)

    #保存公钥
    spub = pubkey.save_pkcs1()
    spubfile = open('serverpublic.pem', 'wb')
    spubfile.write(spub)
    spubfile.close()
    #保存私钥
    spri = privkey.save_pkcs1()
    sprifile = open('serverprivate.pem', 'wb')
    sprifile.write(spri)
    sprifile.close()

#导入server公钥私钥
with open('serverpublic.pem', "rb") as publickfile:
    p = publickfile.read()
    spubkey = rsa.PublicKey.load_pkcs1(p)
with open('serverprivate.pem', "rb") as privatefile:
    p = privatefile.read()
    sprivkey = rsa.PrivateKey.load_pkcs1(p)




while True:
    conn, addr = server.accept()  # 等待连接

    print("conn:", conn, "\naddr:", addr)  # conn连接实例

    while True:
        data = conn.recv(1024)  # 接收
        if not data:  # 客户端已断开
            print("客户端断开连接")
            break
        print("收到的请求:", data.decode("utf-8"))
        cmd, filename = data.decode("utf-8").split(" ")

        if cmd =="get":
            if os.path.isfile(filename):  # 判断文件存在
                conn.send("收到请求！".encode("utf-8"))
                #接收B的公钥
                Bkeydata=conn.recv(251)
                f=open('clientpublic.pem', "wb")
                f.write(Bkeydata)
                f.close()
                print("client公钥接收成功")
                #发送A的公钥
                f=open('serverpublic.pem', "rb")
                Akeydata=f.read(251)
                f.close()
                conn.send(Akeydata)
                print("server公钥发送成功")

                #导入client公钥
                with open('clientpublic.pem', "rb") as publickfile:
                    p = publickfile.read()
                    cpubkey = rsa.PublicKey.load_pkcs1(p)

                #生成会话密钥
                #desKEY='ABCDEFGH' #DES密钥
                desKEY=genrateKey()
                keycrypto = rsa.encrypt(desKEY.encode('utf-8'), cpubkey)

                #发送加密后的会话密钥
                #conn.recv(1024)  # 接收确认
                conn.send(keycrypto)  # 发送数据
                print("会话密钥生成:",desKEY)
                print("会话密钥加密完成")
                print("会话密钥发送成功")

                #读取文件同时生成摘要
                size = os.stat(filename).st_size
                m = hashlib.md5()
                f = open(filename, 'rb')
                plain_text=f.read(size)
                m.update(plain_text) #运送生成md5的材料
                f.close

                #0.加密文件
                efilename="encryped_"+filename #加密后的文件名
                encrypted_text=des_encrypt(plain_text,desKEY)
                f = open(efilename,'wb')
                f.write(encrypted_text)
                f.close()
                
                # 1.先发送文件大小，让客户端准备接收
                size = os.stat(efilename).st_size  #获取文件大小
                conn.send(str(size).encode("utf-8"))  # 发送数据长度
                print("发送的文件大小：", size)

                # 2.发送加密后的文件内容
                conn.recv(1024)  # 接收确认
                f = open(efilename, "rb")
                for line in f:
                    conn.send(line)  # 发送数据
                f.close()
                os.system("rm "+efilename)
                
                # 3.发送md5值进行校验
                md5 = m.hexdigest() #生成摘要
                conn.send(md5.encode("utf-8"))  # 发送md5值
                print("md5:", md5)
                
                #签名
                filesign = rsa.sign(plain_text, sprivkey, 'MD5')
                conn.send(filesign)  # 发送签名
                print("文件传输完成")
            else:
                print("文件不存在!")
                conn.send("文件不存在!".encode("utf-8"))
server.close()
