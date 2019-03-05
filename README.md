# PPF (Process Packet Filtering Machine)

## What is this?

You can find all open ports in specific process, using this program.

So, you can use this informations in wireshark, packet sniffers ... etc.

## Dependency

WinDivert: https://reqrypt.org/windivert.html

## Example

Print all tcp packets.

```
process: -1 (null)
src-port: 80, dest-port: 53667
src: 179.58.45.5, dest: 112.219.168.192
=============================================
process: -1 (null)
src-port: 443, dest-port: 53637
src: 113.255.30.192, dest: 112.219.168.192
=============================================
process: 25424 (uTorrent.exe)
src-port: 44946, dest-port: 39755
src: 112.219.168.192, dest: 252.60.17.183
=============================================
process: -1 (null)
src-port: 53525, dest-port: 5426
src: 1.47.122.68, dest: 1.47.122.84
=============================================
process: 13524 (firefox.exe)
src-port: 53299, dest-port: 53298
src: 1.0.0.127, dest: 1.0.0.127
=============================================
process: 13524 (firefox.exe)
src-port: 53299, dest-port: 53298
src: 1.0.0.127, dest: 1.0.0.127
=============================================
process: -1 (null)
src-port: 80, dest-port: 53668
src: 248.59.45.5, dest: 112.219.168.192
...
```

Print selected process tcp packets.

```
=============================================
process: 4204 (chrome.exe)
src-port: 53804, dest-port: 443
src: 112.219.168.192, dest: 178.132.248.203
 -- 53804 (1)
=============================================
process: 4204 (chrome.exe)
src-port: 53640, dest-port: 443
src: 112.219.168.192, dest: 133.228.101.151
 -- 53640 (1)
 -- 53804 (1)
=============================================
process: 4204 (chrome.exe)
src-port: 53645, dest-port: 443
src: 112.219.168.192, dest: 133.228.101.151
 -- 53640 (1)
 -- 53645 (1)
 -- 53804 (1)
=============================================
process: 4204 (chrome.exe)
src-port: 53643, dest-port: 443
src: 112.219.168.192, dest: 133.228.101.151
 -- 53640 (1)
 -- 53643 (1)
 -- 53645 (1)
 -- 53804 (1)
=============================================
process: 4204 (chrome.exe)
src-port: 53642, dest-port: 443
src: 112.219.168.192, dest: 133.228.101.151
 -- 53640 (1)
 -- 53642 (1)
 -- 53643 (1)
 -- 53645 (1)
 -- 53804 (1)
...
```
