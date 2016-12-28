import socks
import socket

MAX_PACKAGE_SIZE = 99999
def cn():
    PORT = 8080
    HOST = socket.gethostname()
    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS4, "127.0.0.1", PORT)
    socket.socket = socks.socksocket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    return s



s = cn()
while True:
    x = raw_input(">")
    try:
        s.send(x)
        print s.recv(MAX_PACKAGE_SIZE)
    except:
        print 'Connection fail]\nTry again....'

s.close()


