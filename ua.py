#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import sys
import threading
import socket
import time
from collections import namedtuple

import hashlib               #导入功能模块，此模块有MD5,SHA1,SHA256等方法


from ui import Ui_Dialog
from PyQt5.QtWidgets import QApplication, QDialog
from PyQt5 import QtWidgets,QtCore

UA_INFO = namedtuple('UA_INFO',['ip', 'port','name'])

ua = UA_INFO('0.0.0.0',12345,'112')

HOST,UDPPORT = ua.ip,ua.port   #for udp

sips = "11.0.0.3"
call_id = "fjkdlsjfkdlsjfkldsf"

cseq_reg = 1
cseq_call = 1
branch ="jkfljkslj32jkl"
rinstance = "75495jruiou3o2u3"

name2call = "111"

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((HOST,UDPPORT))
#接收缓冲区
# nRecvBuf=2*1024*1024
# s.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,nRecvBuf)
# #发送缓冲区
# nSendBuf=2*1024*1024
# s.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,nSendBuf)



#branch标识一个事务
# sip协议描述一个transaction由5个必要部分组成：from、to、Via头中的branch参数、call-id和cseq
# 这5个部分一起识别某一个transaction，如果缺少任何一部分，该transaction就会设置失败
#call-id 标识一个用户会话

def makeRegisterMsg(sips,ua,branch,tag,call_id,cseq,rinstance):
    cmd = "REGISTER sip:{0};transport=UDP SIP/2.0\r\n".format(sips)
    route = "Via:SIP/2.0/UDP {0}:{1};branch=z9hG4bk-{2}\r\n".format(ua.ip,ua.port,branch)
    maxForward ="Max-Forwards:70\r\n"
    Contact = "Contact:<sip:{0}@{1}:{2};rinstance={3};transport=UDP>\r\n".format(ua.name,ua.name,ua.ip,rinstance)
    To ="To:{0}<sip:{1}@{2};transport=UDP>\r\n".format(ua.name,ua.name,ua.ip)
    From = "From:{0}<sip:{1}@{2};transport=UDP>;tag={3}\r\n".format(ua.name, ua.name,ua.ip,tag)
    Call_id = "Call-ID:{0}\r\n".format(call_id)  #全网唯一
    cseq = "CSeq: {} REGISTER\r\n".format(cseq)
    exp = "Expires: 3600\r\n"
    allow = "Allow: INVITE, ACK, CANCEL, BYE, NOTIFY, REFER, MESSAGE, OPTIONS, INFO, SUBSCRIBE\r\n"
    spt  = "Supported: replaces, norefersub, extended-refer, timer, X-cisco-serviceuri\r\n"
    uagent = "User-Agent: py\r\n"
    allow_ev = "Allow-Events: presence, kpml\r\n"
    cl = "Content-Length: 0\r\n"

    return cmd+route+maxForward+Contact+To+From+Call_id+cseq+exp+uagent+cl

def makeInviteMsg(sips,ua,branch,tag,call_id,cseq,rinstance,name2call):
    cmd = "INVITE sip:{0}@{1};transport=UDP SIP/2.0\r\n".format(name2call,sips)
    route = "Via:SIP/2.0/UDP {0}:{1};branch=z9hG4bk-{2}\r\n".format(ua.ip,ua.port,branch)
    maxForward ="Max-Forwards:70\r\n"
    Contact = "Contact:<sip:{0}@{1}:{2};rinstance={3};transport=UDP>\r\n".format(ua.name,ua.ip,ua.port,rinstance)
    To ="To:<sip:{0}@{1};transport=UDP>\r\n".format(name2call,ua.ip)
    From = "From:{0}<sip:{1}@{2};transport=UDP>;tag={3}\r\n".format(ua.name, ua.name,ua.ip,tag)
    Call_id = "Call-ID:{0}\r\n".format(call_id)  #全网唯一
    cseq = "CSeq: {} INVITE\r\n".format(cseq)
    exp = "Expires: 3600\r\n"
    allow = "Allow: INVITE, ACK, CANCEL, BYE, NOTIFY, REFER, MESSAGE, OPTIONS, INFO, SUBSCRIBE\r\n"
    spt  = "Supported: replaces, norefersub, extended-refer, timer, X-cisco-serviceuri\r\n"
    uagent = "User-Agent:py\r\n"
    allow_ev = "Allow-Events:presence, kpml\r\n"
    ContentType = "Content-Type:application/sdp\r\n"
    cl = "Content-Length: 127\r\n"

    content = "\r\nv=0\r\n"
    content += "o=- 0 0 IN IP4 127.0.0.1\r\n"
    content += "s=session\r\n"
    content += "c=IN IP4 127.0.0.1\r\n"
    content += "b=CT:1000\r\n"
    content += "t=0 0\r\n"
    content += "m=audio 10000 RTP/AVP 8\r\n"
    content += "a=rtpmap:8 PCMA/8000\r\n"

    return cmd+route+maxForward+Contact+To+From+Call_id+cseq+exp+uagent+ContentType+cl+content

def makeAuthMsg(sips,ua,branch,tag,call_id,cseq,rinstance,nonce,realm,responcce,cnonce,nc):
    cmd = "REGISTER sip:{0};transport=UDP SIP/2.0\r\n".format(sips)
    route = "Via:SIP/2.0/UDP {0}:{1};branch=z9hG4bk-{2}\r\n".format(ua.ip,ua.port,branch)
    maxForward ="Max-Forwards:70\r\n"
    Contact = "Contact:<sip:{0}@{1}:{2};rinstance={3};transport=UDP>\r\n".format(ua.name,ua.name,ua.ip,rinstance)
    To ="To:{0}<sip:{1}@{2};transport=UDP>\r\n".format(ua.name,ua.name,ua.ip)
    From = "From:{0}<sip:{1}@{2};transport=UDP>;tag={3}\r\n".format(ua.name, ua.name,ua.ip,tag)
    Call_id = "Call-ID:{0}\r\n".format(call_id)  #全网唯一
    cseq = "CSeq: {} REGISTER\r\n".format(cseq)
    exp = "Expires: 3600\r\n"
    allow = "Allow: INVITE, ACK, CANCEL, BYE, NOTIFY, REFER, MESSAGE, OPTIONS, INFO, SUBSCRIBE\r\n"
    spt  = "Supported: replaces, norefersub, extended-refer, timer, X-cisco-serviceuri\r\n"
    uagent = "User-Agent: py\r\n"
    auth = 'Authorization: Digest '\
            +'username="{}",'.format(ua.name) \
            +'{},'.format(realm) \
            +'{}'.format(nonce) \
            +'uri="sip:{};'.format(sips) \
            +'transport=UDP",response="{}",'.format(responcce) \
            +'cnonce="{}",'.format(cnonce) \
            +'nc={},qop=auth,algorithm=MD5'.format(nc)

    allow_ev = "Allow-Events: presence, kpml\r\n"
    cl = "Content-Length: 0\r\n"

    return cmd+route+maxForward+Contact+To+From+Call_id+cseq+exp+uagent+auth+cl

def processUdpData(s):
    print('udp data monitoring...')
    while True:
        data, addr = s.recvfrom(8192)
        msgRX = data.decode('utf-8','ignore')
        localtime = time.asctime(time.localtime(time.time()))
        print("UA MSG RECEIVED!----------------\n",localtime,"\n",msgRX, addr)  # 注意  如果解码不成功将会导致程序终止
        # 发送数据,此处有一个坑是sendto（）里面的参数必须二进制数据，不能直接传字符串
        decodeSensorData(msgRX)


t = threading.Thread(target=processUdpData,args=(s,))
t.start()

def decodeSensorData(msg): #格式验证和数据提取
    ls = msg.splitlines()
    code =None
    status=None
    seq=None
    cmd=None
    call_id=None
    if not msg:
        return
    for msg in ls:
        if msg.startswith("SIP/2.0"):
            code,status = getAckCode(msg)
            print(code,status)
        elif msg.startswith("CSeq"):
            seq, cmd = getCSeq(msg)
            print(seq, cmd)
        elif msg.startswith("Call-ID"):
            call_id = getCallID(msg)
            print(call_id)
    if cmd == "REGISTER" and code=="200":
        print("ua register successful-------------------------")
    if cmd == "INVITE" and code.startswith('4'):
        print("ua call failed-------------------------")
    if cmd == "REGISTER" and code == "401" and status == "Unauthorized":
        #回复登录密码信息
        genResponce(nonce,username,realm,passwd,method,uri)

def genResponce(nonce,username,realm,passwd,method,uri):
    # 　　1)HASH1 = MD5(username:realm: passwd) #不同字段中间加冒号字符
    #
    # 　　2)HASH2 = MD5(method:uri)
    #
    # 　　3)response = MD5(HA1:nonce: HA2)
    #如果质量保护指定是“auth”或者“auth - int”, 响应结果算法是
    # response = MD5(HA1:nonce:nonceCount:cnonce:qop:HA2)
    def md5(str):
        m = hashlib.md5()  # 声明一个md5对象
        m.update(str.encode('utf-8','ignore'))
        return m.hexdigest()
    # ha1 = md5('115:ltsip.cn:123456')
    ha1 = md5("Mufasa:testrealm@host.com:Circle Of Life")
    print(ha1)
    # ha2 = md5('REGISTER:sip:11.0.0.3')
    ha2 = md5("GET:/dir/index.html")
    print(ha2)
    nonce = "dcd98b7102dd2f0e8b11d0f600bfb0c093"
    cnonce = "0a4f113b"
    # cnonce = "d20ad7febce41cc979e00a1663667608"
    nc = '00000001'#注意为固定8字节，表示请求认证的次数，不加引号
    qop = 'auth'
    res = md5(ha1+':{}:{}:{}:{}:'.format(nonce,nc,cnonce,qop)+ha2)
    print(res)





def getAckCode(msg):
    if not msg.startswith("SIP/2.0"):
        return None
    subs = msg.split(' ')
    if len(subs) < 3:
        return None
    code, status = subs[1], subs[2]
    return (code,status)
def getCSeq(msg):
    if not msg.startswith("CSeq"):
        return None
    subs = msg.split(' ')
    if len(subs) != 3:
        return None
    seq, cmd = subs[1], subs[2]
    return (seq,cmd)
def getCallID(msg):
    if not msg.startswith("Call-ID"):
        return None
    subs = msg.split(' ')
    if len(subs) != 2:
        return None
    call_id = subs[1]
    return call_id

def getAuth(msg):
    if not msg.startswith("WWW-Authenticate"):
        return None
    subs = msg.split(' ')
    if len(subs) < 4:
        return None
    realm,nonce, algorithm = subs[2], subs[3], subs[4]
    return (realm,nonce,algorithm)

# regmsg = makeRegisterMsg(sips,ua,branch,"1233ffs",call_id,cseq_reg,rinstance)
# s.sendto(regmsg.encode('utf-8','ignore'),("127.0.0.1",5060))


class MyDialog(QtWidgets.QDialog,Ui_Dialog):
    mySignal = QtCore.pyqtSignal(int)
    def __init__(self):
        super(MyDialog,self).__init__()
        self.setupUi(self)

        self.pushButtonReg.clicked.connect(self.sendReg) #

        self.pushButtonCall.clicked.connect(self.sendCall) #注意此处的myFun不带括号
        #
        # self.dial.valueChanged.connect(self.myFun3)  #信号和槽都不带括号，与qt中使用区别

    def sendReg(self):
        global cseq_reg, cseq_call
        regmsg = makeRegisterMsg(sips, ua, branch, "1233ffs", call_id, cseq_reg, rinstance)
        s.sendto(regmsg.encode('utf-8', 'ignore'), (sips, 5060))
        cseq_reg += 1
        print("ua Sent register msg............\n",regmsg)

    def sendCall(self):
        global cseq_reg, cseq_call
        callmsg = makeInviteMsg(sips, ua, branch, "1fdsffdsffs", call_id, cseq_call, rinstance,name2call)
        s.sendto(callmsg.encode('utf-8', 'ignore'), (sips, 5060))
        cseq_call += 1
        print("ua Sent calling msg............\n", callmsg)

    def sendAuth(self,num):
        # self.lcdNumber.display(num)
        pass

if __name__ == '__main__':
    app = QApplication(sys.argv)
    dlg1 = MyDialog()
    dlg1.show()
    sys.exit(app.exec_())


