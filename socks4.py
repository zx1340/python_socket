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

port, logfile, dumplen, printmode, hijack, olddata, newdata, ignore = 9999, '', 16, 'hex', '', '', '', ''
colorama.init()


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
    if logfile != '':
        file = open(logfile, 'ab+')
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
        myopts, args = getopt.getopt(sys.argv[1:], 'p:l:x:t:h:i:')
    except getopt.GetoptError as e:
        print (str(e))
        print 'Usage: %s [options]\nOptions:' \
              '\n-p port (listen port)' \
              '\n-l logfile (traffic log)' \
              '\n-x hexlength (hex length to print, default is 16)' \
              '\n-t text/hex (display mode: text or hex'\
              '\n-h s/r:olddata:newdata (data replacement, s is send, r is recv)'\
              '\n-i s/h:ignore (ignore for replacement, h for hex input'\
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


class Packet():
    def __init__(self,package,data):
        self.package = package
        self.data = data



class Datahandle():
    def __init__(self):
        self.allpk = {}
    
    def addpk(self,package,data):
        self.allpk[str(len(self.allpk))] = Packet(package,data)




class MSock4(SOCKSv4):

    def runCommand(self,cmd,datahandle):
        print 'calc command',cmd,len(cmd.split(' '))
        if len(cmd.split(' ')) < 2:
            print '[E] Command error'

        if len(cmd.split(' ')) == 2:
            command = cmd.split(' ')[0]
            args = cmd.split(' ')[1]
            if command == 'repeat':

                repeat_package = datahandle.allpk[args].package
                print '[REPEAT]',getCSInfo(repeat_package),datahandle.allpk[args].data
                SOCKSv4.dataReceived(repeat_package,datahandle.allpk[args].data)

            elif command == 'print':
                print_package = datahandle.allpk[args].package

                print '[PRINT]',getCSInfo(print_package)
                data = datahandle.allpk[args].data
                print colored(hexdump(data), 'red')

            else:
                print "[E] Not implement"


        if len(cmd.split(' ')) == 3:
            command = cmd.split(' ')[0]
            arg1 = cmd.split(' ')[1]
            arg2 = cmd.split(' ')[2]

            if command == 'compare':
                pckg1_data = datahandle.allpk[arg1].data
                pckg2_data = datahandle.allpk[arg2].data
                #for i in pckg1_data:






            print "[E] Not implement"
        return


    def dataReceived(self, data):
        global datahandle

        if not self.otherConn:
            return SOCKSv4.dataReceived(self, data)

        if hijack == 's':
            data = editdata(data)

        
        cs = getCSInfo(self)
        if cs[0] == '127.0.0.1':
            print '[>] Excute command:',data
        
            self.runCommand(data,datahandle)
            

            return SOCKSv4.dataReceived(self,data)
        

        datahandle.addpk(self,data)
        #return SOCKSv4.dataReceived(self,data)
        
        csinfo = '%s:%s --> %s:%s' % getCSInfo(self)
        csinfo += ' len: %s' % len(data)
        print colored(csinfo, 'red')
        print colored(hexdump(data), 'green')

        logdata('%s\n%s' % (csinfo, hexdump(data)))
        

        print '[TOTAL PACKAGE]', len(datahandle.allpk)
        return SOCKSv4.dataReceived(self, data)


    def write(self, data):
        global datahandle

        

        if not self.otherConn:
            return SOCKSv4.write(self, data)

        if hijack == 'r':
            data = editdata(data)
        
        cs = getCSInfo(self)

        datahandle.addpk(self,data)
        return SOCKSv4.write(self, data)

        csinfo = '%s:%s <-- %s:%s' % getCSInfo(self)
        csinfo += ' len: %s' % len(data)
        print colored(csinfo, 'red')
        print colored(hexdump(data), 'yellow')


        logdata('%s\n%s' % (csinfo, hexdump(data)))

        print '[TOTAL PACKAGE]', len(datahandle.allpk)

        return SOCKSv4.write(self, data)



datahandle = Datahandle()
filter = '49.213.119.232'

if __name__ == '__main__':
    main(sys.argv)
