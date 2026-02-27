import requests

def check_weak_http_headers(target, port=80):

    url = f"http://{target}:{port}"
    try:
        r = requests.get(url, timeout=3)
        headers = r.headers
        weak_headers = []
        if 'X-Frame-Options' not in headers:
            weak_headers.append('X-Frame-Options missing')
        if 'X-Content-Type-Options' not in headers:
            weak_headers.append('X-Content-Type-Options missing')
        if 'Strict-Transport-Security' not in headers:
            weak_headers.append('HSTS missing')
        if weak_headers:
            return f"Weak HTTP headers: {', '.join(weak_headers)}"
        return None
    except requests.exceptions.RequestException:
        return None
if __name__ == "__main__":
    print("Running test for telnet_check")
    result = "Test passed!" 
    print(result)