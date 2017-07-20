# sockproxy
Socks4 is simple python script to monitor network and modify before send.
### USING
*It woking on window and linux now
* Open first cmd
```sh
>python socksproxy.py
```
Example output:
```

127.0.0.1:60298 <-- 198.35.26.112:443 len: 113 id: 32
00000000:  14 03 03 00 01 01 16 03 03 00 20 a4 7e 06 e4 fa   .......... .~...
00000010:  e7 cb 4c 70 08 7f 8f e4 b0 d2 b8 d0 fd 74 d7 33   ..Lp.........t.3
00000020:  3f 39 ae 1d 42 4b 8b e7 4a cc ed 17 03 03 00 41   ?9..BK..J......A
127.0.0.1:60303 <-- 216.58.221.228:443 len: 46 id: 45
00000000:  17 03 03 00 29 00 00 00 00 00 00 00 05 ee 51 44   ....).........QD
00000010:  d4 89 0d 1f 4b 5b f6 c5 b4 8b 65 9d 1f 4f 99 c4   ....K[....e..O..
00000020:  72 2e a0 38 3d 1d bf 43 e3 cd 75 08 44 1e         r..8=..C..u.D.
127.0.0.1:60306 <-- 216.58.221.238:443 len: 544 id: 55
00000000:  17 03 03 00 d1 00 00 00 00 00 00 00 04 94 fd d4   ................
00000010:  06 bd 9a 7d 9e de ff f9 24 63 b8 51 e1 86 3c af   ...}....$c.Q..<.
.......
```
* Open second cmd
```sh
>python client.py
>[Command]
```
Using client file to enter command, it send command to socks4 and get the result.
Example:
```sh
>filter sendonly
[I]Mode Send turned on
>filter info
{'BanIP': [], 'Size': [], 'Mode': 'Send', 'Port': []}
>filter nofilter
[I]No Filter now
>print 12
('127.0.0.1', 59564, '54.169.224.56', 443)
00000000:  16 03 03 00 ca 04 00 00 c6 00 00 01 2c 00 c0 bc   ............,...
00000010:  cd 9c 22 3e 37 d3 c9 69 fa c0 ee 1b 80 7c f3 9b   ..">7..i.....|..
00000020:  fa d8 2b 62 f0 fa 7a 6f 92 23 a8 62 8e ad 63 95   ..+b..zo.#.b..c.
```
### Command
>print [package] 

* show infomation about this package

>get [package]
 
 * get hex encoding of package 

>repeat [package] 

* resend this package

>replace [package] [location] [value]

 * replace one character of package and resend
 
>diff [first_package] [second_package]

* diffirent between 2 package ( need using same size package )

>send [package] [data]

 * resend hex encoded data define by package id ( sender, recver, using "get" command to get encoded package data )

>filter [command]
 
 * filter command using to filter packet show on socks4

### FILTER 
>filter info

 * Get current filter

>filter addport [port]
>filter removeport [port]
 * Port filter

>filter ip [ip]
 
 * Just follow given ip

>filter len [package_size]

 * Only this size show up

>filter sendonly
>filter recvonly

 * Only send or recv show up.


>filter replace <s/r/b> [hex] <old_string> <new_string>
 
 * filter mode [s]end, [r]recv, [b]oth hex(encode) 

 * Modify package before send

###conclusion
This program gen file pkg.log store all package data
Using strings pkg.log to get all strings
