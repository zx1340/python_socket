import socks
import socket

PORT = 8080
HOST = socket.gethostname()

socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS4, "127.0.0.1", PORT)
socket.socket = socks.socksocket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

#name = raw_input("What is your command? ")

#s.send("print 357")
#s.close()