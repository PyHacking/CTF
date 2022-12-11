1)See source code
2) Access the directory: http://photobomb.htb/photobomb.js
```javascript
function init() {
  // Jameson: pre-populate creds for tech support as they keep forgetting them and emailing me
  if (document.cookie.match(/^(.*;)?\s*isPhotoBombTechSupport\s*=\s*[^;]+(.*)?$/)) {
    document.getElementsByClassName('creds')[0].setAttribute('href','http://pH0t0:b0Mb!@photobomb.htb/printer');
  }
}
window.onload = init;
http://pH0t0:b0Mb!@photobomb.htb/printer
```
3) In this row we can obtain the credentials"http://pH0t0:b0Mb!@photobomb.htb/printer');":
```
Username: pH0t0
Password : b0Mb!
```