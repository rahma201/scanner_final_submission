import socket

def check_smb(target, port=445):
    """
    Basic SMB exposure check.
    Checks if SMB port is open (possible guest/null exposure).
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((target, port))
        s.close()

        return {
            "service": "SMB",
            "port": port,
            "issue": "SMB service exposed (possible guest/null access risk)",
            "risk": "Medium",
            "evidence": f"Port {port} is open on {target}"
        }

    except Exception:
        return None


if __name__ == "__main__":
    target = "192.168.56.101"
    result = check_smb(target)
    print(result)

