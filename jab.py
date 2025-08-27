#!/usr/bin/python
from os import system, popen
import socket
import ssl
from base64 import b64encode, b64decode
from utils import *
import hashlib, hmac
from sys import argv, stderr
from multiprocessing import Process

global my_xid 
global my_username 
global my_xmpphost
global from_ 
global from_xid 
global to_xid 
global to_username 
global to_xmpphost
global to 


def xml(ct):
        return "<message type='chat' to='"+to_xid+"' from='"+from_xid+"'><body>.</body><x xmlns='jabber:x:encrypted'>"+ct+"</x></message>"


if argv[1] == '--from':
        my_xid = argv[2]
        my_username = my_xid.split('@')[0]
        my_xmpphost= my_xid.split('@')[1]
        from_ = my_username
        from_xid = my_xid
if argv[3] == '--to':
        to_xid = argv[4]
        to_username = to_xid.split('@')[0]
        to_xmpphost= my_xid.split('@')[1]
        to = to_username
if argv[7] == '--my-keyid':
        my_keyid = argv[8]
if argv[9] == '--recp-keyid':
        recp_keyid = argv[10]


pass_file = argv[6]
my_password = open(pass_file, "r").read().strip()

id=''
a =" <stream:stream version='1.0' to='"+my_xmpphost+"' xml:lang='en' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>"
b = "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
c = "<stream:stream from='"+my_xid+"'  to='"+my_xmpphost+"' version='1.0' xml:lang='en' xmlns='jabber:client' id='"+id+"' xmlns:stream='http://etherx.jabber.org/streams'>"

def auth(s, my_password):
    # TCP
    print('[-] negotiating TLS from TCP')
    s.sendall(a.encode())
    x = s.recv(2048)
    x = x.decode()
    id = str(x.split('id=\'')[1].split('\'')[0])
    s.sendall(b.encode())
    x = s.recv(2048)
    # TLS
    context = ssl.create_default_context()
    ss = context.wrap_socket(s, server_hostname=my_xmpphost) 
    ss.sendall(c.encode())
    x = ss.read(1024)
    print('[+] TLS enabled')
    # SASL
    print('[-] negotiating SASL SCRAM-SHA-1')
    clientNonce = popen("tr -cd '\'' -~'\'' < /dev/urandom |fold -w 32 |head -n1").read()
    c_msg1 = b64encode(byte("n,,n="+my_username+",r=" + clientNonce))
    c_msg1_no_gs2_header = "n="+my_username+",r=" + clientNonce
    d = b"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='SCRAM-SHA-1'>"+c_msg1+b"</auth>"
    ss.write(d)
    s_msg1_full = ss.read(9999)
    # print(s_msg1_full)
    ddd = b''
    # if my_xmpphost=='conversations.im':
    #         e = b"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='SCRAM-SHA-1'>"+c_msg1+b"</auth>"
    #         ss.write(e)
    #         print("C: "+str(e))
    #         s_msg1_full = ss.read(9999)
    #         print("s: "+str(s_msg1_full))
    tmp = s_msg1_full.decode().split('<challenge xmlns=\'urn:ietf:params:xml:ns:xmpp-sasl\'>')[1]
    chal_b64 = tmp.split('</challenge>')[0]
    chal = b64decode(chal_b64).decode()
    s_msg1_rsi = chal
    chal_split = chal.split(',')
    r = chal_split[0][2:]
    s = chal_split[1][2:]
    s = b64decode(s) # bin
    i = int(chal_split[2][2:])
    # compute <response>
    normalizedPassword = byte(saslprep(my_password))
    serverFirstMessage = s_msg1_rsi
    initialMessage = str(c_msg1_no_gs2_header)
    clientFinalMessageBare = "c=biws,r=" + r
    saltedPassword = hashlib.pbkdf2_hmac('sha1', normalizedPassword, s, i)
    clientKey = hmac.HMAC(saltedPassword, b"Client Key", digestmod=hashlib.sha1).digest() # bin
    m = hashlib.sha1()
    m.update(clientKey)
    storedKey = m.digest() # bin
    authMessage = initialMessage + "," + serverFirstMessage + "," + clientFinalMessageBare # str
    clientSignature = hmac.HMAC(storedKey, byte(authMessage), digestmod=hashlib.sha1).digest() # bin
    clientProof = xor(clientKey, clientSignature) # bin
    clientFinalMessage = byte(clientFinalMessageBare) + b",p=" + b64encode(clientProof) # bin
    f = b"<response xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\">"+b64encode(clientFinalMessage)+b"</response>"
    ss.write(f)
    ss.read(9999)
    j = "<stream:stream from='"+my_xid+"' to='"+my_xmpphost+"' version='1.0' xml:lang='en' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>"
    j = j.encode()
    ss.write(j)
    x = ss.read(9999)
    # print(x) # <------------- conversations.im: b"<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-authorized/><text xml:lang='en'>Nonce mismatch</text></failure>"
    k="<iq id='qwejkdfrty' type='set'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>balcony</resource></bind></iq>"
    k = k.encode()
    ss.write(k)
    x = ss.read(9999)
    print('[+] SASL negotiation successful')
    print('[+] Logged in as '+my_xid)
    return ss

################ PGP (XEP-0027) #####################
# ''' gpg --armor -u user1 -e --output - -r user2 -r user1 msg '''
def encrypt_nosign(msg):
        system("echo " + msg + ">msg")
        # TODO: encrypt message from STDIN (can attacker see it in bash history?)
        # TODO(?) remove "-r user1" (i wont be able to decrypt messages i sent if i retreive them using MAM)
        # to = "tarb"
        ct = str(popen("gpg --armor -u" + my_keyid + " -e  --output - -r" + recp_keyid + " -r " + my_keyid + " msg").read()).split('\n')
        system("rm msg")
        ct = ct[2:-2]
        ct = "".join(ct)
        return ct

def encrypt_signonly(msg):
        system("echo " + msg + ">msg")
        ct = str(popen("gpg --armor -u" + my_keyid + " --sign --output - msg").read()).split('\n')
        system("rm msg")
        ct = ct[2:-2]
        ct = "".join(ct)
        return ct

def decrypt_noverify(msg):
        system("echo '-----BEGIN PGP MESSAGE-----\n' >> msg.asc")
        system("echo " + msg + ">>msg.asc")
        system("echo '\n-----END PGP MESSAGE-----' >> msg.asc")
        plain = str(popen("gpg -d msg.asc 2>/dev/null").read()).split('\n')[0]
        # TODO add error handling: if it cant decrypt
        system("rm msg.asc")
        return plain






def send_presence(ss, msg):
        l="<presence from='"+my_xid+"' to='"+to_xid+"'><status>Online</status><x xmlns='jabber:x:signed'>"+encrypt_signonly(msg)+"</x></presence>"
        ss.sendall(l.encode())
        log_w(l)

def write_():
        i = 0
        while True:
                # i += 1
                # if i == 5:
                #         send_request(ss) 
                #         i = 0
                # inp = input()
                inp = input("\033[94m")
                print("\033[0m", end='')
                # print("\033[0m", end='')
                if inp[0] == '/':
                        g = inp.split(' ')
                        if g[0] == '/last':
                                read_last(g[1], g[2])
                                continue
                ct = encrypt_nosign(inp)
                stanza = xml(ct)
                log_w(stanza)
                ss.sendall(stanza.encode())
                n = "<message type='chat' to='"+to_xid+"'><active xmlns='http://jabber.org/protocol/chatstates'/></message>"
                ss.sendall(n.encode())
                log_w(n)
                print("\033[1A" + "\033[1K", end='')
                # print("\033[0m", end='')
                print("<"+my_username+"> "+inp)
                print("\033[0m", end='')
                # if i == 0:      # on first write, retreive last 10 messages from server archive (MAM)
                #         # read_last(1)
                #         p.start() # cant cal recv() on 1 socket twice
                #         i = 1


def read_():
        # i = 0
        while True:
                # if i == 0:
                #         i += 1
                #         ss.settimeout(1)
                #         try:
                #                 stanza = ss.recv(9999)
                #         except: 
                #                 ss.settimeout(0)
                #                 continue
                # i += 1
                # if i == 5:
                #         send_request(ss) 
                #         i = 0
                # ss.setblocking(False)
                # send_reSquest()
                stanza = ss.recv(2048)
                stanza = stanza.decode()
                log_r(stanza)
                # is msg from to_xid? if not, continue
                # TODO
                # ignore composing and other messages
                try:
                        stanza = stanza.split('jabber:x:encrypted\'>')[1]
                except:
                        try:
                                stanza = stanza.split('<body>')[1]
                                stanza = "".join(stanza)
                                plain = stanza.split('</body>')[0]
                                print("\033[0m", end='')
                                system("echo "+"\'\033[0m<"+to_username+"> [e] "+plain+"\033[94m\'")
                                continue
                        except:
                                continue

                stanza = "".join(stanza)
                ct = stanza.split('</x>')[0]
                pt= decrypt_noverify(ct)
                print("\033[0m", end='')
                system("echo "+"\'\033[0m<"+to_username+"> [E] "+pt+"\033[94m\'")

# jab cant read messages until it sends a message,
# then all messages come flooding in

def read_last(num, acc):
        """
        [ ] TODO: clean up system() calls, they are prone to command injection
        [ ] TODO: find a way for this to work while read_() already is recv()'ing via the socket ss
        https://xmpp.org/extensions/xep-0313.html
        """
        xml="<iq type='set' id='nig'><query xmlns='urn:xmpp:mam:2'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE' type='hidden'><value>urn:xmpp:mam:2</value></field><field var='with'><value>"+acc+"</value></field></x><set xmlns='http://jabber.org/protocol/rsm'><max>"+str(num)+"</max><before/></set></query></iq>"
        ss.sendall(xml.encode())
        # log_w(xml)
        stanza_stream = ss.recv(9999)
        stanza_stream = stanza_stream.decode()
        log_r(stanza_stream)

        b=[0]*int(num)
        a = stanza_stream.split('<message')
        del a[0]
        i = j = 0
        while 1:
                _body=''
                _from=''
                try:
                        b[i] = a[j] + a[j+1]
                        j += 2
                        i += 1
                except:
                        break
        for stanza in b:
                try:
                        _from=stanza.split('from=\'')[1].split('\'')[0]
                except: 
                        break
                _stamp=stanza.split('stamp=\'')[1].split('\'')[0]
                try:
                        _body=stanza.split('<body>')[1].split('</body>')[0]
                except:
                        # gajim issue
                        pass
                try:
                        _ct=stanza.split('\'jabber:x:encrypted\'>')[1].split('</x>')[0]
                        _pt= decrypt_noverify(_ct)
                        print("\033[0m", end='')
                        system("echo "+"\'\033[0m"+_stamp+" <"+_from+"> [E] "+_pt+"\033[94m\'") # _pt -> ;ls  (command injection) RCE bug TOFIX 
                        continue
                except:
                        pass
                if _body == None:
                        print("\033[0m", end='')
                        system("echo "+"\'\033[0m"+_stamp+" <"+_from+"> [e] "+_body+"\033[94m\'") 

def send_request():
        j = "<r xmlns='urn:xmpp:sm:3'/>"
        j = j.encode()
        ss.sendall(j)
        x = ss.recv(2048)
        # print("C: "+str(j))
        # print("S: "+str(x))
        return

def enable_stream_management():
    j = "<enable xmlns='urn:xmpp:sm:3'/>"
    j = j.encode()
    ss.write(j)
    x = ss.read(9999)
    # print(j)
    # print(x)
    send_request()
    # print('[+] Enabled Stream Management (XEP-0198) partial support')



s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((my_xmpphost, 5222))
ss = auth(s, my_password)
# send_presence(ss, "Online")
enable_stream_management()
read_last(10, to_xid)
p = Process(target=read_)
p.start()
write_()

# <message to='user2@yax.im' from='testuser@xmpp.tld.pro'><body>.</body><x xmlns='jabber:x:encrypted'></x></message>
# <message to='user1@conversations.im' from='testuser@xmpp.tld.pro'><body>.</body><x xmlns='jabber:x:encrypted'></x></message>

# DEBUG
# ss.settimeout(2)
# i = 0
# while 1:
#         i += 1
#         if i == 5:
#                 send_request(ss)
#                 i = 0
#         # dd = input("C: ")
#         # dd = dd.encode()
#         # ss.write(dd)
#         # ss.setblocking(False)
#         # aa = ss.recv(9999)
#         # print("S: "+aa.decode())
#         xml="<iq type='set' id='nig'><query xmlns='urn:xmpp:mam:2'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE' type='hidden'><value>urn:xmpp:mam:2</value></field><field var='with'><value>"+to_xid+"</value></field></x><set xmlns='http://jabber.org/protocol/rsm'><max>1</max><before/></set></query></iq>"
#         print(xml)
#         ss.sendall(xml.encode())
#         stanza = ss.recv(9999)
#         stanza = stanza.decode()
#         print(stanza)
#         print('==============================================================================')
#         exit(0)

# <iq type='set' id='balcony'>
# <query xmlns='urn:xmpp:mam:2'>
# <x xmlns='jabber:x:data' type='submit'>
# <field var='FORM_TYPE' type='hidden'>
# <value>urn:xmpp:mam:2</value>
# </field>
# <field var='start'>
# <value>2025-02-16T00:00:00Z</value>
# </field>
# </x></query></iq>

# <iq type='set' id='nig'><query xmlns='urn:xmpp:mam:2'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE' type='hidden'><value>urn:xmpp:mam:2</value></field><field var='with'><value>user2@xmpp.tld</value></field><field var='start'><value>2025-02-17T00:00:00Z</value></field></x><set xmlns='http://jabber.org/protocol/rsm'><max>1</max><before/></set></query></iq>
# p.join()

