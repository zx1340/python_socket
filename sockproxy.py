#!/usr/bin/env python
"""
superkhung@vnsecurity.net
a socks4 server based on twisted framework
it can be use to log/modify network traffic
"""

from twisted.internet.protocol import Factory
from twisted.internet import reactor
from twisted.protocols.socks import SOCKSv4
from termcolor import colored
import sys
import getopt
import colorama
import socket
import os

port, full_capture = 8080, False
printmode = 'hex'
dumplen = 16
colorama.init()




class Packet():
    def __init__(self,package,Mode,data):
        self.package = package
        self.mode = Mode
        self.data = data





class Datahandle():
    def __init__(self):
        self.allpk = {}
    
    def addpk(self,package,Mode,data):
        self.allpk[str(len(self.allpk))] = Packet(package,Mode,data)





def hexdump(src, sep='.'):
    if printmode == 'text' or full_capture == False:
        return src

    length = dumplen
    FILTER = ''.join(
        [(len(repr(chr(x))) == 3) and chr(x) or sep for x in range(256)])
    lines = []
    for c in xrange(0, len(src), length):
        chars = src[c:c + length]
        hex = ' '.join(['%02x' % ord(x) for x in chars])
        # if len(hex) > 24:
        #    hex = '%s %s' % (hex[:24], hex[24:])
        printable = ''.join(
            ['%s' % ((ord(x) <= 127 and FILTER[ord(x)]) or sep) for x in chars])
        lines.append('%08x:  %-*s  %s\n' % (c, length * 3, hex, printable))
    return ''.join(lines)




def logpackage(data):
    file = open('pkg.log', 'ab+')
    file.write(data + '\n')
    file.close()



def getCSInfo(self):
    peer = self.transport.getPeer()
    other_peer = self.otherConn.transport.getPeer()
    sip = peer.host
    sport = peer.port
    dip = other_peer.host
    dport = other_peer.port

    return sip, sport, dip, dport


def editdata(data):
    if len(ignore) > 0:
        inputformat = ignore[0]
        ignorelist = ignore[1:]
        for i in ignorelist:
            if inputformat == 'h':
                i = i.decode('hex')
            if data.find(i) != -1:
                return data

    data = data.replace(olddata, newdata)
    return data


def main(argv):

    os.system('rm -rf pkg.log')
    os.system('rm -rf zx.log')

    global port, full_capture

    try:
        myopts, args = getopt.getopt(sys.argv[1:], 'p:f')
    except getopt.GetoptError as e:
        print (str(e))
        print 'Usage: %s [options]\nOptions:' \
              '\n-p port (listen port)' \
              '\n-f full capture' \
              '\n' % (sys.argv[0])
        sys.exit(2)

    for o, a in myopts:
        if o == '-p':
            port = int(a)
        elif o == '-f':
            full_capture = True
        
    factory = Factory
    factory.protocol = MSock4
    reactor.listenTCP(port, factory())
    print 'Listen port: %s\nFull capture: %s' % (port, str(full_capture))
    reactor.run()




def rpl(string,position,value):
    return string[0:position] + value + string[position + 1:]




def strdiff(x,y):

    if len(x) != len(y):
        return 'Cannot compare two diffirent package size'

    hx = hexdump(x)
    hy = hexdump(y)


    diff = [i for i in xrange(len(hx)) if hx[i] != hy[i]]

    rx = ''
    ry = ''
    for i in diff:
        if i % 77 < 58:
            if hx[i+1] == ' ' and (i-1) not in diff:
                diff.append(i-1)
            elif hx[i-1] == ' ' and (i+1) not in diff:
                diff.append(i+1)
            else:
                pass

    for i in range(len(hx)):
        if i in diff:
            rx += colored(hx[i],'red')
            ry += colored(hy[i],'red')
        else:
            rx += hx[i]
            ry += hy[i]

    return rx + '\n' + ry


def changeFilter(command):
    global Filter
    
        #filter addport 443
    if command[1] == 'info':
        return str(Filter)


    if command[1] == 'addport':
        
        if len(command) != 3:
            return '[E]Using:filter addport <Port>'

        if command[2] in Filter['Port']:
            return '[I]This Port already filted'
        

        Filter['Port'].append(command[2])
        return '[I]Port %s added successfull' % (command[2])

    if command[1] == 'removePort':
        if len(command) != 3:
            return '[E]Using:filter removePort <Port>'

        if command[2] not in Filter['Port']:
            return '[E]Need add Port before remove it'
        
        Filter['Port'].remove(command[2])
        return '[I]Remove Port successfull'

    if command[1] == 'ip':
        if len(command) != 3:
            return '[E]Using:filter ip <ip>'
        if command[2] in Filter['IP']:
            return '[I]Done'

        Filter['IP'].append(command[2])
        return '[I]Adding ip filter successfull'



    if command[1] == 'len':
        if len(command) != 3:
            return '[E]Using: filter len <package_size>'
        
        try:
            int(command[2])
        except:
            return '[E]Invalid package size'

        if command[2] in Filter['Size']:
            return '[I]Done'
        

        Filter['Size'].append(command[2])
        return '[I]Current filter package size: %s ' % (str(Filter['Size']))





    if command[1] == 'replace':
        if len(command) < 5:
            return '[E]Using:filter replace <s/r/b> [hex] <old_string> <new_string>'

        rpl_type = command[2]
        
        if rpl_type not in ['s','r','b']:
            return '[E]Using replace [s]end [r]eceive or [b]oth'
        
        if len(command) == 6:
            if command[3] == 'hex':
                try:
                    old_string = command[4].decode('hex')
                    new_string = command[5].decode('hex')
                except:
                    return '[E]Need encoded hex string'
        
        else:

            old_string = command[3]
            new_string = command[4]
        
        if len(old_string) != len(new_string):
            return '[E]Need same size encode string'

        Filter['replace'].append( (rpl_type,old_string,new_string) )
        
        return '[I]Filter:' + str(Filter['replace'])



    if command[1] == 'sendonly':
        Filter['Mode'] = 'Send'
        return '[I]Mode Send turned on'
    if command[1] == 'recvonly':
        Filter['Mode'] = 'Recv'
        return '[I]Mode recv turned on'


    if command[1] == 'reset':
        Filter = {
        'Mode':None,
        'Port':[],
        'Size':[],
        'ip':[],
        'replace':[]
        }

        return '[I]No Filter now'

    return '[E]Unidentified filter'



def using():
    return '[-]repeat <package_id>\n[-]print <package_id>\n[-]diff <package_id_1> <package_id_2>\n[-]replace <package_id> <location> <value>\n[-]send <package_id> <encode_hex_string>\n[-]filter [addport|removeport|sendonly|recvonly] + [port]'


class MSock4(SOCKSv4):



    def handlePackage(self,Mode,data):
        #check filter and print out
        #ignore web traffic
        if not full_capture:
            if data[0:4] != 'POST' and data[0:3] != 'GET':
                return data


        global datahandle

        datahandle.addpk(self,Mode,data)

        csinfo = getCSInfo(self)

        if Filter['Mode'] == 'Send' and Mode == 'Send': return data
        if Filter['Mode'] == 'Recv' and Mode == 'Recv': return data
        if len(Filter['ip']):
            if csinfo[0] not in Filter['ip'] and csinfo[2] not in Filter['ip']: return data



        if len(Filter['Size']):
            if str(len(data)) not in Filter['Size']:
                return data

        

        if len(Filter['replace']):
            for rpl in Filter['replace']:
                rpl_type = rpl[0]
                old_str = rpl[1]
                new_str = rpl[2]
                if rpl_type == 's' or rpl_type == 'b':
                    if Mode == "Send":
                        if old_str in data:
                            data = data.replace(old_str,new_str)
                
                if rpl_type == 'r' or rpl_type == 'b':
                    if Mode == 'Recv':
                        if old_str in data:
                            data = data.replace(old_str,new_str)

        prtcsinfo = '%s:%s --> %s:%s' % csinfo if Mode == 'Send' else '%s:%s <-- %s:%s' % csinfo 
        prtcsinfo += ' len: %s' % len(data)
        prtcsinfo += ' id: %s' % (len(datahandle.allpk) - 1)


        print colored(prtcsinfo, 'red')
        print colored(hexdump(data), 'yellow') if Mode == 'Send' else colored(hexdump(data), 'green')
        logpackage(prtcsinfo)
        logpackage(data)
        return data


    def runCommand(self,cmd):
        
        ret = ()
        
        print '[Excute]',cmd
        
        if len(cmd.split(' ')) < 2:
            #print '[E] Command error'
            return '[E]Unidentified command\n' + using()
        
        command = cmd.split(' ')

        if command[0] == 'repeat':
            if len(command) != 2:
                return '[E]Using: repeat <package_id>'

            else:
                pckg_id = command[1]
                try:
                    if int(pckg_id) >= len(datahandle.allpk):
                        return '[E]Invalid package id, current %s' %(len(datahandle.allpk) - 1) 
                except:
                    return '[E]Invalid package id'

                repeat_package = datahandle.allpk[pckg_id].package
                data = datahandle.allpk[pckg_id].data
                mode = datahandle.allpk[pckg_id].mode
                if mode == 'Recv':
                    SOCKSv4.dataReceived(repeat_package,datahandle.allpk[pckg_id].data)
                else:
                    SOCKSv4.write(repeat_package, datahandle.allpk[pckg_id].data)


                return str(getCSInfo(repeat_package)) + '\n' +  str(colored(hexdump(data), 'red'))

        elif command[0] == 'print':
            if len(command) != 2:
                return '[E]Using: print <package_id>' 
            else:
                
                pckg_id = command[1]
                try:
                    if int(pckg_id) >= len(datahandle.allpk):
                        return '[E]Invalid package id, current %s' %(len(datahandle.allpk) - 1) 
                except:
                    return '[E]Invalid package id'

                print_package = datahandle.allpk[pckg_id].package
                data = datahandle.allpk[pckg_id].data
                return str(getCSInfo(print_package)) + '\n' +  str(colored(hexdump(data), 'red')) + '\n'
        
        elif command[0] == 'get':
            if len(command) != 2:
                return '[E]Using: print <package_id>' 
            else:
                pckg_id = command[1]
                try:
                    if int(pckg_id) >= len(datahandle.allpk):
                        return '[E]Invalid package id, current %s' %(len(datahandle.allpk) - 1) 
                except:
                    return '[E]Invalid package id'
                print_package = datahandle.allpk[pckg_id].package
                data = datahandle.allpk[pckg_id].data
                return str(getCSInfo(print_package)) + '\n' + data.encode('hex')


        elif command[0] == 'diff':
            if len(command) != 3:
                return '[E]Using: diff <package_id_1> <package_id_2>'
            else:
                pckg1_id = cmd.split(' ')[1]
                pckg2_id = cmd.split(' ')[2]
                try:
                    if int(pckg1_id) >= len(datahandle.allpk) or int(pckg2_id) >= len(datahandle.allpk):
                        return '[E]Invalid package id, current %s' %(len(datahandle.allpk) - 1) 
                except:
                    return '[E]Invalid package id'

                pckg1_data = datahandle.allpk[pckg1_id].data
                pckg2_data = datahandle.allpk[pckg2_id].data
                ret = strdiff(pckg1_data,pckg2_data)
                return ret


        elif command[0] == 'replace':
            if len(command) != 4:
                return '[E]Using: replace <package_id> <location> <value>'
            
            pckg_id = command[1]

            try:
                if int(pckg_id) >= len(datahandle.allpk):
                    return '[E]Invalid package id, current %s' %(len(datahandle.allpk) - 1)
            except:
                return '[E]Invalid package id'

            location = command[2]
            value = command[3]
            rpl_pckg = datahandle.allpk[pckg_id].package
            data = datahandle.allpk[pckg_id].data
            data = rpl(data,int(location),chr(int('0x' + value,16)))
            SOCKSv4.dataReceived(rpl_pckg,data)
            
            return colored(hexdump(data),'green')


        elif command[0] == 'send':
            if len(command) != 3:
                return '[E]Using: send <package_id> <encode_hex_string>'
            else:

                pckg_id = command[1]

                try:
                    if int(pckg_id) >= len(datahandle.allpk):
                        return '[E]Invalid package id, current %s' %(len(datahandle.allpk) - 1)

                except:
                    return '[E]Invalid package id'

                data = command[2].decode('hex')
                
                rpl_pckg = datahandle.allpk[pckg_id].package

                SOCKSv4.dataReceived(rpl_pckg,data)
                return '[I]Packet send without error'


        elif command[0] == 'filter':
            # if len(command) != 2 and len(command) != 3 and len(command) != 4:
            #     return '[E]Using: filter [addport|removeport|sendonly|recvonly|replace] + [port|str] + [/str]'
            # else:
            return changeFilter(command)

        else:
            return '[E]Unidentified command\n' + using()


    def dataReceived(self, data):

        if not self.otherConn:
            return SOCKSv4.dataReceived(self, data)

        
        cs = getCSInfo(self)

        if cs[0] == '127.0.0.1' and cs[2] == '127.0.0.1':
            print '[<] Excute command:',data
            ret = self.runCommand(data)
            return SOCKSv4.write(self,ret)


        data = self.handlePackage('Recv',data)
        
        return SOCKSv4.dataReceived(self, data)


    def write(self, data):
        
        if not self.otherConn:
            return SOCKSv4.write(self, data)

        
        data = self.handlePackage('Send',data)
        

        return SOCKSv4.write(self, data)




datahandle = Datahandle()
Filter = {
    'Mode':None,
    'Port':[],
    'Size':[],
    'ip':[],
    'replace':[]

}

if __name__ == '__main__':
    main(sys.argv)
