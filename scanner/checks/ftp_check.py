import socket


def check_ftp(target, port=21):
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((target, port))
        banner = s.recv(1024).decode(errors="ignore")
        s.close()

        # This is just a simple demo heuristic. Real anonymous login check would require auth attempt.
        if "anonymous" in banner.lower():
            return f"FTP may allow anonymous login (banner mentions anonymous): {banner.strip()}"

        return None

    except (ConnectionRefusedError, TimeoutError, socket.timeout):
        # Service not running / filtered => not a finding
        return None

    except OSError as e:
        # Common "service not available" errors should not be treated as findings
        msg = str(e).lower()
        if "connection refused" in msg or "timed out" in msg or "network is unreachable" in msg:
            return None
        return f"FTP check error: {e}"
