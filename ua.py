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

UA_INFO = namedtuple('UA_INFO',['ip', 'port','rtp_port','name','passwd'])

ua = UA_INFO('11.0.0.88',12345,10000,'112','123456')

HOST,UDPPORT = ua.ip,ua.port   #for udp

sips = "11.0.0.3"
sips_port = "5060"
call_id = "fjkdlsjfkdlsjfkldsf"

cseq_reg = 1
cseq_call = 1
branch ="jkfljkslj32jkl"
rinstance = "75495jruiou3o2u3"
tag = '23u292jotjo'
nc = '00000001'#注意为固定8字节，表示请求认证的次数，不加引号

tag_in = None

cnonce = "d20ad7febce41cc979e00a1663667608"

name2call = "111"

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((HOST,UDPPORT))
#接收缓冲区
# nRecvBuf=2*1024*1024
# s.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,nRecvBuf)
# #发送缓冲区
# nSendBuf=2*1024*1024
# s.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,nSendBuf)

def md5(str):
    m = hashlib.md5()  # 声明一个md5对象
    m.update(str.encode('utf-8', 'ignore'))
    return m.hexdigest()

#branch标识一个事务
# sip协议描述一个transaction由5个必要部分组成：from、to、Via头中的branch参数、call-id和cseq
# 这5个部分一起识别某一个transaction，如果缺少任何一部分，该transaction就会设置失败
#call-id 标识一个用户会话

def makeRegisterMsg(sips,ua,branch,tag,call_id,cseq,rinstance):
    cmd = "REGISTER sip:{0};transport=UDP SIP/2.0\r\n".format(sips)
    route = "Via:SIP/2.0/UDP {0}:{1};branch=z9hG4bk-{2}\r\n".format(ua.ip,ua.port,branch)
    maxForward ="Max-Forwards:70\r\n"
    Contact = "Contact:<sip:{0}@{1}:{2};rinstance={3};transport=UDP>\r\n".format(ua.name,ua.ip,ua.port,rinstance)
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
    content += "o=- 0 0 IN IP4 {}\r\n".format(ua.ip)
    content += "s=session\r\n"
    content += "c=IN IP4 {}\r\n".format(ua.ip)
    content += "b=CT:1000\r\n"
    content += "t=0 0\r\n"
    content += "m=audio {} RTP/AVP 8\r\n".format(ua.rtp_port)
    content += "a=rtpmap:8 PCMA/8000\r\n"

    return cmd+route+maxForward+Contact+To+From+Call_id+cseq+exp+uagent+ContentType+cl+content

def makeAuthMsg(sips,ua,branch,tag,call_id,cseq,rinstance,nonce,realm,responcce,nc):
    cmd = "REGISTER sip:{0};transport=UDP SIP/2.0\r\n".format(sips)
    route = "Via:SIP/2.0/UDP {0}:{1};branch=z9hG4bk-{2}\r\n".format(ua.ip,ua.port,branch)
    maxForward ="Max-Forwards:70\r\n"
    Contact = "Contact:<sip:{0}@{1}:{2};rinstance={3};transport=UDP>\r\n".format(ua.name,ua.ip,ua.port,rinstance)
    To ="To:{0}<sip:{1}@{2};transport=UDP>\r\n".format(ua.name,ua.name,ua.ip)
    From = "From:{0}<sip:{1}@{2};transport=UDP>;tag={3}\r\n".format(ua.name, ua.name,ua.ip,tag)
    Call_id = "Call-ID:{0}\r\n".format(call_id)  #全网唯一
    cseq = "CSeq: {} REGISTER\r\n".format(cseq)
    exp = "Expires: 3600\r\n"
    allow = "Allow: INVITE, ACK, CANCEL, BYE, NOTIFY, REFER, MESSAGE, OPTIONS, INFO, SUBSCRIBE\r\n"
    spt  = "Supported: replaces, norefersub, extended-refer, timer, X-cisco-serviceuri\r\n"
    uagent = "User-Agent: py\r\n"
    #注意auth中的双引号
    auth = 'Authorization: Digest '\
            +'username="{}",'.format(ua.name) \
            +'realm="{}",'.format(realm) \
            +'nonce="{}",'.format(nonce) \
            +'uri="sip:{};transport=UDP",'.format(sips) \
            +'response="{}",'.format(responcce) \
            +'cnonce="{}",'.format(cnonce) \
            +'nc={},qop=auth,algorithm=MD5'.format(nc)

    allow_ev = "Allow-Events: presence, kpml\r\n"
    cl = "Content-Length: 0\r\n"

    return cmd+route+maxForward+Contact+To+From+Call_id+cseq+exp+uagent+auth+cl

def makeInviteAck(sips,ua,branch,tag_local,call_id,cseq_ack,tag_incoming):
    cmd = "ACK sip:{0}@{1}:{2};transport=UDP SIP/2.0\r\n".format(name2call,sips,sips_port)
    route = "Via:SIP/2.0/UDP {0}:{1};branch=z9hG4bk-{2}\r\n".format(ua.ip,ua.port,branch)
    maxForward ="Max-Forwards:70\r\n"
    Contact = "Contact:<sip:{0}@{1}:{2};transport=UDP>\r\n".format(ua.name,ua.ip,ua.port)
    To ="To:<sip:{0}@{1};transport=UDP>;tag={2}\r\n".format(name2call,sips,tag_incoming)
    From = "From:{0}<sip:{1}@{2};transport=UDP>;tag={3}\r\n".format(ua.name, ua.name,sips,tag_local)
    Call_id = "Call-ID:{0}\r\n".format(call_id)  #全网唯一
    cseq = "CSeq: {} ACK\r\n".format(cseq_ack)
    uagent = "User-Agent: py\r\n"
    cl = "Content-Length: 0\r\n"
    content = "\r\n"
    return cmd+route+maxForward+Contact+To+From+Call_id+cseq+uagent+cl+content

def makeByeMsg(sips,ua,branch,tag_local,call_id,cseq_ack,tag_incoming):
    cmd = "BYE sip:{0}@{1}:{2};transport=UDP SIP/2.0\r\n".format(name2call,sips,sips_port)
    route = "Via:SIP/2.0/UDP {0}:{1};branch=z9hG4bk-{2}\r\n".format(ua.ip,ua.port,branch)
    maxForward ="Max-Forwards:70\r\n"
    Contact = "Contact:<sip:{0}@{1}:{2};transport=UDP>\r\n".format(ua.name,ua.ip,ua.port)
    To ="To:<sip:{0}@{1};transport=UDP>;tag={2}\r\n".format(name2call,sips,tag_incoming)
    From = "From:{0}<sip:{1}@{2};transport=UDP>;tag={3}\r\n".format(ua.name, ua.name,sips,tag_local)
    Call_id = "Call-ID:{0}\r\n".format(call_id)  #全网唯一
    cseq = "CSeq: {} ACK\r\n".format(cseq_ack)
    uagent = "User-Agent: py\r\n"
    cl = "Content-Length: 0\r\n"
    content = "\r\n"
    return cmd+route+maxForward+Contact+To+From+Call_id+cseq+uagent+cl+content

def makeAckBYE(sips,ua,branch,tag_local,call_id,cseq_ack,tag_incoming):
    cmd = "SIP/2.0 200 OK\r\n".format(name2call,sips,sips_port)
    route = "Via:SIP/2.0/UDP {0}:{1};branch=z9hG4bk-{2}\r\n".format(ua.ip,ua.port,branch)
    maxForward ="Max-Forwards:70\r\n"
    Contact = "Contact:<sip:{0}@{1}:{2};transport=UDP>\r\n".format(ua.name,ua.ip,ua.port)
    To ="To:<sip:{0}@{1};transport=UDP>;tag={2}\r\n".format(name2call,sips,tag_incoming)
    From = "From:{0}<sip:{1}@{2};transport=UDP>;tag={3}\r\n".format(ua.name, ua.name,sips,tag_local)
    Call_id = "Call-ID:{0}\r\n".format(call_id)  #全网唯一
    cseq = "CSeq: {} ACK\r\n".format(cseq_ack)
    uagent = "User-Agent: py\r\n"
    cl = "Content-Length: 0\r\n"
    content = "\r\n"
    return cmd+route+maxForward+Contact+To+From+Call_id+cseq+uagent+cl+content


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
    call_id=None
    nonce = None
    realm = None
    method = None
    qop = None
    tag_to = None
    if not msg:
        return
    for msg in ls:
        if msg.startswith("SIP/2.0"):
            code,status = getAckCode(msg)
            print(code,status)
        elif msg.startswith("CSeq"):
            seq, method = getCSeq(msg)
            print(seq, method)
        elif msg.startswith("Call-ID"):
            call_id = getCallID(msg)
            print(call_id)
        elif msg.startswith("WWW-Authenticate"):
            realm, nonce, algorithm, qop = getAuth(msg)
            print(realm, nonce, algorithm, qop)
        elif msg.startswith("To"):
            tag_to = getToInfo(msg)
            print(tag_to)
        elif msg.startswith("From"):
            tag_in = getFromInfo(msg)
            print(tag_in)
        elif msg.startswith("Invite"):#入境会话请求
            tag_to = getInvitedInfo(msg)
        elif msg.startswith("BYE"):  # 入境会话取消消息
            method, ua_tobye = getByeInfo(msg)
            print(tag_to)
    if method == "REGISTER" and code=="200":
        print("ua register successful-------------------------")
    if method == "INVITE" and not code: #有入境呼叫
        print("ua having a comming call-------------------------")

    if method == "INVITE" and code: #本地主叫方收到服务器的呼叫回复消息
        if code == "200":#对方已接受会话,则本地主叫方应回复ACK给服务器
            ackMsg = makeInviteAck(sips,ua,branch,'1fdsffdsffs',call_id,1,tag_to)
            sendACKInvite(ackMsg)
            print("ua is on the wire-------------------------")
        if code.startswith('4'):
            print('call failed due to "{}"'.format(status))
    if method == "REGISTER" and code == "401" and status == "Unauthorized":
        #回复登录密码信息
        resp= genResponce(nonce,ua.name,realm,ua.passwd,method,qop)
        authmsg = makeAuthMsg(sips,ua,branch,tag,call_id,cseq_reg,rinstance,nonce,realm,resp,nc)
        sendAuth(authmsg)
        print('sent auth__________',authmsg)
    if method == "BYE": #收到BYE消息，给服务器回复ACK
        ackMsg = makeAckBYE(sips,ua,branch_incoming,tag,call_id_incoming,cseq_incoming,tag_incoming)
        sendACKInvite(ackMsg)
        print("ua is call ended with incoming 'BYE'-------------------------")

def genResponce(nonce,username,realm,passwd,method,qop):
    # 普通认证方法：容易破解
    # 　　1)HASH1 = MD5(username:realm: passwd) #不同字段中间加冒号字符
    # 　　2)HASH2 = MD5(method:uri)
    # 　　3)response = MD5(HA1:nonce: HA2)
    #如果质量保护指定是“auth”或者“auth - int”, 响应结果算法是
    # response = MD5(HA1:nonce:nonceCount:cnonce:qop:HA2)
    ha1 = md5('{}:{}:{}'.format(username,realm,passwd))

    uri = 'sip:{};transport=UDP'.format(sips)
    ha2 = md5('{}:{}'.format(method,uri))
    res = md5(ha1+':{}:{}:{}:{}:'.format(nonce,nc,cnonce,qop)+ha2)
    print('RESPONCE:\n',res)
    return res

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

def getToInfo(msg):
    if not msg.startswith("To"):
        return None
    i = msg.find('tag=')
    if i < 0:
        return None
    tag = msg[i:].strip('tag=')
    return tag

def getFromInfo(msg):
    if not msg.startswith("From"):
        return None
    i = msg.find('tag=')
    if i < 0:
        return None
    tag = msg[i:].strip('tag=')
    return tag

def getInvitedInfo(msg):
    if not msg.startswith("INVITE"):
        return None
    subs = msg.split(' ')
    if len(subs) < 3:
        return None
    request, ua_incoming = subs[0], subs[1]
    return (request,ua_incoming)

def getByeInfo(msg):
    if not msg.startswith("BYE"):
        return None
    subs = msg.split(' ')
    if len(subs) < 3:
        return None
    request, ua_incoming = subs[0], subs[1]
    return (request,ua_incoming)

def getAuth(msg):
    #例子'WWW-Authenticate: Digest realm="ltsip.cn", nonce="02fbfa80e68e9c1bc189975eaeadc6cb", algorithm=MD5, qop="auth"'
    #注意字符串中的逗号和引号
    if not msg.startswith("WWW-Authenticate"):
        return None
    msgr = msg.replace(',',' ').replace('\"','')  #替换原有的逗号为空格,并去掉引号
    subs = msgr.split(' ')
    if len(subs) < 5:
        return None
    realm = None
    nonce = None
    algorithm = None
    qop = None
    for ss in subs:
        if ss.startswith("realm"):
            realm = ss.replace('realm=','')
            print('realm:',realm)
        elif ss.startswith("nonce"):
            nonce = ss.replace('nonce=','')
        elif ss.startswith("algorithm"):
            algorithm = ss.replace('algorithm=','')
        elif ss.startswith("qop"):
            qop = ss.replace('qop=','')
    return (realm,nonce,algorithm,qop)

def sendAuth(authmsg):
    global cseq_reg
    s.sendto(authmsg.encode('utf-8', 'ignore'), (sips, 5060))
    cseq_reg += 1
    print("ua Sent register msg............\n",authmsg)

def sendACKInvite(ackmsg):
    s.sendto(ackmsg.encode('utf-8', 'ignore'), (sips, 5060))
    print("ua Sent register msg............\n",ackmsg)

class MyDialog(QtWidgets.QDialog,Ui_Dialog):
    mySignal = QtCore.pyqtSignal(int)
    def __init__(self):
        super(MyDialog,self).__init__()
        self.setupUi(self)

        self.pushButtonReg.clicked.connect(self.sendReg) #

        self.pushButtonCall.clicked.connect(self.sendCall) #注意此处的myFun不带括号
        self.pushButtonCancelCall.clicked.connect(self.sendBye)
        #
        # self.dial.valueChanged.connect(self.myFun3)  #信号和槽都不带括号，与qt中使用区别

    def sendReg(self):
        global cseq_reg, cseq_call
        regmsg = makeRegisterMsg(sips, ua, branch, "tag", call_id, cseq_reg, rinstance)
        s.sendto(regmsg.encode('utf-8', 'ignore'), (sips, 5060))
        cseq_reg += 1
        print("ua Sent register msg............\n",regmsg)

    def sendCall(self):
        global cseq_reg, cseq_call
        callmsg = makeInviteMsg(sips, ua, branch, "1fdsffdsffs", call_id, cseq_call, rinstance,name2call)
        s.sendto(callmsg.encode('utf-8', 'ignore'), (sips, 5060))
        cseq_call += 1
        print("ua Sent calling msg............\n", callmsg)

    def sendBye(self):
        global cseq_call
        bye = makeByeMsg(sips, ua, branch, "1fdsffdsffs", call_id, cseq_call, tag_in)
        s.sendto(bye.encode('utf-8', 'ignore'), (sips, 5060))
        cseq_call += 1
        print("ua Sent calling msg............\n", bye)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    dlg1 = MyDialog()
    dlg1.show()
    sys.exit(app.exec_())


