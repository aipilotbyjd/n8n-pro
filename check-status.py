#!/usr/bin/env python3
import socket
import json

def test_port(host, port):
    """Test if a port is open"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

def test_api():
    """Test API endpoints"""
    try:
        import urllib.request
        response = urllib.request.urlopen('http://localhost:8080/health', timeout=5)
        return {
            'status': 'success',
            'http_code': response.getcode(),
            'data': response.read().decode()
        }
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e)
        }

if __name__ == "__main__":
    print("=== n8n-pro API Status Check ===")
    
    # Check port 8080
    port_open = test_port('localhost', 8080)
    print(f"Port 8080 open: {port_open}")
    
    if port_open:
        # Test health endpoint
        result = test_api()
        print(f"API Health: {result}")
    else:
        print("Port 8080 is not accessible")