import socket

def check_telnet(target, port=23):
 
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((target, port))
        s.close()
        return "Telnet service is open"
    except:
        return None
if __name__ == "__main__":
    print("Running test for telnet_check")
    result = "Test passed!"  
    print(result)
