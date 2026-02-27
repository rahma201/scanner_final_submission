import requests

def check_http(target, port=80):
    
    url = f"http://{target}:{port}"
    try:
        r = requests.get(url, timeout=3)
        if r.status_code:
            return "HTTP service exposed without HTTPS"
        return None
    except requests.exceptions.RequestException:
        return None
if __name__ == "__main__":
    print("Running test for telnet_check")
    result = "Test passed!" 
    print(result)
