import socket, time
for i in range(100):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 8080))
    s.send(b"GET /?test=eval(")
    print(f"[{i}] Sent 1st package")
    s.send(b"base64_decode HTTP/1.1\r\n\r\n")
    print(f"[{i}] Sent 2nd package")
    s.close()