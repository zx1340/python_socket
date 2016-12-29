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


port, logfile, dumplen, printmode, hijack, olddata, newdata, ignore = 8080, '', 16, 'hex', '', '', '', ''
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
    if printmode == 'text':
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




def logdata(data):
    #if logfile != '':
    file = open('zx.log', 'ab+')
    file.write(data + '\n')
    file.close()


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
    global port, logfile, dumplen, printmode, hijack, olddata, newdata, ignore

    try:
        myopts, args = getopt.getopt(sys.argv[1:], 'p:l:x:t')
    except getopt.GetoptError as e:
        print (str(e))
        print 'Usage: %s [options]\nOptions:' \
              '\n-p port (listen port)' \
              '\n-l logfile (traffic log)' \
              '\n-x hexlength (hex length to print, default is 16)' \
              '\n-t text/hex (display mode: text or hex'\
              '\n' % (sys.argv[0])
        sys.exit(2)

    for o, a in myopts:
        if o == '-p':
            port = int(a)
        elif o == '-l':
            logfile = a
        elif o == '-x':
            dumplen = int(a)
        elif o == '-t':
            printmode = a
        elif o == '-h':
            hijack, olddata, newdata = a.split(':')
        elif o == '-i':
            ignore = a.split(':')

    factory = Factory
    factory.protocol = MSock4
    reactor.listenTCP(port, factory())
    print 'Listen port: %s\nLog file: %s\nHex length %s\nPrint mode: %s' % (port, logfile, dumplen, printmode)
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
            return '[E]Using:filter addport <port>'

        if command[2] in Filter['port']:
            return '[I]This port already filted'
        

        Filter['port'].append(command[2])
        return '[I]Port %s added successfull' % (command[2])

    if command[1] == 'removeport':
        if len(command) != 3:
            return '[E]Using:filter removeport <port>'

        if command[2] not in Filter['port']:
            return '[E]Need add port before remove it'
        
        Filter['port'].remove(command[2])
        return '[I]Remove port successfull'

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
        if len(command) != 4:
            return '[E]Using:filter replace <encode_hex_string> <encode_hex_string>'

        if len(command[2]) != len(command[3]):
            return '[E]Need same size encode string'


        str1 = command[2].decode('hex')
        str2 = command[3].decode('hex')

        Filter['replace'][str1] = str2

        return '[I]Filter:' + str(Filter['replace'])



    if command[1] == 'sendonly':
        Filter['Mode'] = 'Send'
        return '[I]Mode Send turned on'
    if command[1] == 'recvonly':
        Filter['Mode'] = 'Recv'
        return '[I]Mode recv turned on'



    if command[1] == 'nofilter':
        Filter = {
        'Mode':None,
        'Port':[],
        'Size':[],
        'ip':[],
        'replace':{}
        }

        return '[I]No Filter now'

    return '[E]Unidentified filter'



def using():
    return '[-]repeat <package_id>\n[-]print <package_id>\n[-]diff <package_id_1> <package_id_2>\n[-]replace <package_id> <location> <value>\n[-]send <package_id> <encode_hex_string>\n[-]filter [addport|removeport|sendonly|recvonly] + [port]'


class MSock4(SOCKSv4):



    def handlePackage(self,Mode,data):
        #check filter and print out
        
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
            for i in Filter['replace'].keys():
                if i in data:
                    logdata("__FOUND__|" + i )    
                    data = data.replace(i,Filter['replace'][i])

        prtcsinfo = '%s:%s <-- %s:%s' % csinfo
        prtcsinfo += ' len: %s' % len(data)
        prtcsinfo += ' id: %s' % (len(datahandle.allpk) - 1)


        print colored(prtcsinfo, 'red')
        print colored(hexdump(data), 'yellow') if Mode == 'Send' else colored(hexdump(data), 'green')
        logdata(prtcsinfo)
        logdata(hexdump(data))
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
                SOCKSv4.dataReceived(repeat_package,datahandle.allpk[pckg_id].data)
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
            if len(command) != 2 and len(command) != 3 and len(command) != 4:
                return '[E]Using: filter [addport|removeport|sendonly|recvonly|replace] + [port|str] + [/str]'
            else:
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


        data = self.handlePackage('Send',data)
        
        return SOCKSv4.dataReceived(self, data)


    def write(self, data):
        
        if not self.otherConn:
            return SOCKSv4.write(self, data)

        if hijack == 'r':
            data = editdata(data)
        
        
        data = self.handlePackage('Recv',data)
        

        return SOCKSv4.write(self, data)




datahandle = Datahandle()
Filter = {
    'Mode':None,
    'Port':[],
    'Size':[],
    'ip':[],
    'replace':{}

}

if __name__ == '__main__':
    main(sys.argv)
