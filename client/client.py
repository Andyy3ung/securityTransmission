# client

import socket
import os
import hashlib
import rsa
from pyDes import des, CBC, PAD_PKCS5
import binascii

def des_descrypt(s,KEY):
    secret_key = KEY
    iv = secret_key
    k = des(secret_key, CBC, iv, pad=None, padmode=PAD_PKCS5)
    de = k.decrypt(binascii.a2b_hex(s), padmode=PAD_PKCS5)
    return de

def clientstart(ipadd,cnport):
    if os.path.isfile('clientpublic.pem'):  # 判断密钥对文件存在
        pass
    else:
        # 先生成一对密钥，然后保存.pem格式文件，当然也可以直接使用
        (pubkey, privkey) = rsa.newkeys(1024)

        #保存公钥
        cpub = pubkey.save_pkcs1()
        cpubfile = open('clientpublic.pem', 'wb')
        cpubfile.write(cpub)
        cpubfile.close()
        #保存私钥
        cpri = privkey.save_pkcs1()
        cprifile = open('clientprivate.pem', 'wb')
        cprifile.write(cpri)
        cprifile.close()


    #导入client公钥私钥
    with open('clientpublic.pem', "rb") as publickfile:
        p = publickfile.read()
        cpubkey = rsa.PublicKey.load_pkcs1(p)
    with open('clientprivate.pem', "rb") as privatefile:
        p = privatefile.read()
        cprivkey = rsa.PrivateKey.load_pkcs1(p)


    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # 生成socket连接对象

    ip_port =(ipadd, cnport)  # 地址和端口号

    client.connect(ip_port)  # 连接

    print("服务器已连接")



    while True:
        content = input(">>")

        if len(content)==0: continue  # 如果传入空字符会阻塞

        if content.startswith("get"):
            client.send(content.encode("utf-8"))  # 传送和接收都是bytes类型
            
            if(client.recv(1024).decode("utf-8")=="文件不存在!"):
                print("server responds: 文件不存在！")
                continue

            #发送B的公钥
            f=open('clientpublic.pem', "rb")
            Bkeydata=f.read(251)
            f.close()
            client.send(Bkeydata)
            print("client公钥发送成功")
            #接收A的公钥
            Akeydata=client.recv(251)
            f=open('serverpublic.pem', "wb")
            f.write(Akeydata)
            f.close()
            print("server公钥接收成功")

            #导入server公钥
            with open('serverpublic.pem', "rb") as publickfile:
                p = publickfile.read()
                spubkey = rsa.PublicKey.load_pkcs1(p)

            #接收会话密钥
            keycrypto = client.recv(128)
            print("会话密钥接收成功")
            desKEY= rsa.decrypt(keycrypto, cprivkey)
            print("会话密钥解密完成")
            print('会话密钥:',desKEY.decode("utf-8"))

            # 1.先接收长度
            server_response = client.recv(1024)
            file_size = int(server_response.decode("utf-8"))

            print("接收到的大小：", file_size)

            # 2.接收文件内容
            client.send("准备好接收".encode("utf-8"))  # 接收确认

            filename = "new" + content.split(" ")[1]
            f = open(filename, "wb")
            received_size = 0

            while received_size < file_size:
                size = 0  # 准确接收数据大小，解决粘包
                if file_size - received_size > 1024: # 多次接收
                    size = 1024
                else:  # 最后一次接收完毕
                    size = file_size - received_size

                data = client.recv(size)  # 多次接收内容，接收大数据
                data_len = len(data)
                received_size += data_len
                print("已接收：", int(received_size/file_size*100), "%")
                f.write(data)

            f.close()

            print("实际接收的大小:", received_size)  # 解码

            m = hashlib.md5()
            f = open(filename, "rb")
            encrypted_text=f.read(received_size)
            f.close()

            #解密文件内容
            descrypted_text=des_descrypt(encrypted_text,desKEY)
            m.update(descrypted_text) #运送生成md5的材料
            f=open("descrypted_"+filename,'wb')
            f.write(descrypted_text)
            f.close()

            #删除临时文件
            os.system("mv "+"descrypted_"+filename+" "+content.split(" ")[1])
            os.system("rm "+filename)

            
            # 3.md5值校验
            md5_sever = client.recv(32).decode("utf-8")
            md5_client = m.hexdigest()
            print("服务器发来的md5:", md5_sever)
            print("接收文件的md5:", md5_client)
            if md5_sever == md5_client:
                print("MD5值校验成功")
            else:
                print("MD5值校验失败")
            
            sever_sign = client.recv(1024)
            flag=1
            try:
                rsa.verify(descrypted_text, sever_sign, spubkey)
            except rsa.pkcs1.VerificationError:
                print("签名校验失败")
                flag=0
            if(flag):
                print("签名校验成功")


    client.close()

if __name__ == "__main__":
    clientstart("localhost", 9999)

