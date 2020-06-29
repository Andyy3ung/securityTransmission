#!/usr/bin/env python
# -*- coding: utf-8 -*-

from tkinter import *
import time
import socket
import os
import hashlib
import rsa
from pyDes import des, CBC, PAD_PKCS5
import binascii

LOG_LINE_NUM = 0

class MY_GUI():
    def __init__(self,init_window_name):
        self.init_window_name = init_window_name

    #设置窗口
    def set_init_window(self):
        self.init_window_name.title("混合加密文件传输客户端")  #窗口名                     
        self.init_window_name.geometry('768x450+10+10')                          #320 160为窗口大小，+10 +10 定义窗口弹出时的默认展示位置
        self.init_window_name["bg"] = "pink"                                    #窗口背景色，其他背景色见：blog.csdn.net/chl0000/article/details/7657887
        self.init_window_name.attributes("-alpha",0.9)                          #虚化，值越小虚化程度越高
        #标签
        self.ip_label = Label(self.init_window_name, text="IP地址:",bg="pink")
        self.ip_label.place(relx=0,rely=0.1)

        self.port_label = Label(self.init_window_name, text="Port端口:",bg="pink")
        self.port_label.place(relx=0,rely=0.2)

        self.file_label = Label(self.init_window_name, text="文件名:",bg="pink")
        self.file_label.place(relx=0,rely=0.3)

        self.log_label = Label(self.init_window_name, text="日志:",bg="pink")
        self.log_label.place(relx=0.3,rely=0.05)

        #文本框
        self.ip_Text = Text(self.init_window_name, width=15, height=1)  #ip
        self.ip_Text.place(relx=0.1,rely=0.1)

        self.port_Text = Text(self.init_window_name, width=15, height=1)  #port
        self.port_Text.place(relx=0.1,rely=0.2)

        self.file_Text = Text(self.init_window_name, width=15, height=1)  #port
        self.file_Text.place(relx=0.1,rely=0.3)

        self.log_data_Text = Text(self.init_window_name, width=70, height=28)  # 日志框
        self.log_data_Text.place(relx=0.3,rely=0.1)

        #按钮
        self.client_button = Button(self.init_window_name, text="Get File",bg="lightblue", width=10,command=self.client)  # 调用内部方法  加()为直接调用
        self.client_button.place(relx=0.1,rely=0.4)

    def write_log_to_Text(self,logmsg):
        global LOG_LINE_NUM
        current_time = self.get_current_time()
        logmsg_in = str(current_time) +" " + str(logmsg) + "\n"      #换行
        if LOG_LINE_NUM <= 28:
            self.log_data_Text.insert(END, logmsg_in)
            LOG_LINE_NUM = LOG_LINE_NUM + 1
        else:
            self.log_data_Text.delete(1.0,2.0)
            self.log_data_Text.insert(END, logmsg_in)

    #功能函数
    def client(self):
        ip=self.ip_Text.get(1.0,END).strip().replace("\n","")
        port=self.port_Text.get(1.0,END).strip().replace("\n","")
        filename=self.file_Text.get(1.0,END).strip().replace("\n","")
        self.clientstart(ip, port, filename)

    #获取当前时间
    def get_current_time(self):
        current_time = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
        return current_time


    #日志动态打印
    def des_descrypt(self,s,KEY):
        secret_key = KEY
        iv = secret_key
        k = des(secret_key, CBC, iv, pad=None, padmode=PAD_PKCS5)
        de = k.decrypt(binascii.a2b_hex(s), padmode=PAD_PKCS5)
        return de

    def clientstart(self,ipadd,cnport,fn):

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

        ip_port =(ipadd, int(cnport))  # 地址和端口号

        client.connect(ip_port)  # 连接

        print("服务器已连接")
        self.write_log_to_Text("连接到 "+ipadd+":"+cnport+" 获取文件 "+fn)
        content = "get "+fn

        if len(content)==0: 
            pass  # 如果传入空字符会阻塞

        elif content.startswith("get"):
            client.send(content.encode("utf-8"))  # 传送和接收都是bytes类型
            
            if(client.recv(1024).decode("utf-8")=="文件不存在!"):
                self.write_log_to_Text("server responds: 文件不存在！")
                pass
            else:

                #发送B的公钥
                f=open('clientpublic.pem', "rb")
                Bkeydata=f.read(251)
                f.close()
                client.send(Bkeydata)
                self.write_log_to_Text("client公钥发送成功")
                #接收A的公钥
                Akeydata=client.recv(251)
                f=open('serverpublic.pem', "wb")
                f.write(Akeydata)
                f.close()
                self.write_log_to_Text("server公钥接收成功")

                #导入server公钥
                with open('serverpublic.pem', "rb") as publickfile:
                    p = publickfile.read()
                    spubkey = rsa.PublicKey.load_pkcs1(p)

                #接收会话密钥
                keycrypto = client.recv(128)
                self.write_log_to_Text("会话密钥接收成功")
                desKEY= rsa.decrypt(keycrypto, cprivkey)
                self.write_log_to_Text("会话密钥解密完成")
                self.write_log_to_Text('会话密钥:'+desKEY.decode("utf-8"))

                # 1.先接收长度，建议8192
                server_response = client.recv(1024)
                file_size = int(server_response.decode("utf-8"))

                self.write_log_to_Text("接收到的大小："+ str(file_size))

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
                    self.write_log_to_Text("已接收："+str(int(received_size/file_size*100))+ "%")
                    f.write(data)

                f.close()

                self.write_log_to_Text("实际接收的大小:"+ str(received_size))  # 解码

                m = hashlib.md5()
                f = open(filename, "rb")
                encrypted_text=f.read(received_size)
                f.close()

                #解密文件内容
                descrypted_text=self.des_descrypt(encrypted_text,desKEY)
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
                self.write_log_to_Text("服务器发来的md5:"+ md5_sever)
                self.write_log_to_Text("接收文件的md5:"+md5_client)
                if md5_sever == md5_client:
                    self.write_log_to_Text("MD5值校验成功")
                else:
                    self.write_log_to_Text("MD5值校验失败")
                    
                sever_sign = client.recv(1024)
                flag=1
                try:
                    rsa.verify(descrypted_text, sever_sign, spubkey)
                except rsa.pkcs1.VerificationError:
                    self.write_log_to_Text("签名校验失败")
                    flag=0
                if(flag):
                    self.write_log_to_Text("签名校验成功")


        client.close()



def gui_start():
    init_window = Tk()              #实例化出一个父窗口
    ZMJ_PORTAL = MY_GUI(init_window)
    # 设置根窗口默认属性
    ZMJ_PORTAL.set_init_window()
    init_window.mainloop()          #父窗口进入事件循环，可以理解为保持窗口运行，否则界面不展示





if __name__ == "__main__":
    gui_start()
    
