from socket import *

for i in range(2**16):
    try:
        print(socket(AF_PACKET, SOCK_RAW, i))
    except Exception:
        pass
    try:
        print(socket(AF_PACKET, SOCK_DGRAM, i))
    except Exception:
        pass
    try:
        print(socket(AF_PACKET, SOCK_STREAM, i))
    except Exception:
        pass
    try:
        print(socket(AF_PACKET, SOCK_SEQPACKET, i))
    except Exception:
        pass
    try:
        print(socket(AF_INET, SOCK_RAW, i))
    except Exception:
        pass
    try:
        print(socket(AF_INET, SOCK_DGRAM, i))
    except Exception:
        pass
    try:
        print(socket(AF_INET, SOCK_STREAM, i))
    except Exception:
        pass
    try:
        print(socket(AF_INET, SOCK_SEQPACKET, i))
    except Exception:
        pass
    try:
        print(socket(AF_INET6, SOCK_RAW, i))
    except Exception:
        pass
    try:
        print(socket(AF_INET6, SOCK_DGRAM, i))
    except Exception:
        pass
    try:
        print(socket(AF_INET6, SOCK_STREAM, i))
    except Exception:
        pass
    try:
        print(socket(AF_INET6, SOCK_SEQPACKET, i))
    except Exception:
        pass
    try:
        print(socket(AF_UNIX, SOCK_RAW, i))
    except Exception:
        pass
    try:
        print(socket(AF_UNIX, SOCK_DGRAM, i))
    except Exception:
        pass
    try:
        print(socket(AF_UNIX, SOCK_STREAM, i))
    except Exception:
        pass
    try:
        print(socket(AF_UNIX, SOCK_SEQPACKET, i))
    except Exception:
        pass
