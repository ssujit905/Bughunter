import requests
from urllib.parse import urlparse

# SQL Injection Detection
def check_sql_injection(url):
    sql_payloads = [
        "' OR 1=1 --", 
        "' OR 'a'='a", 
        '" OR 1=1 --', 
        '" OR "a"="a', 
        "'; DROP TABLE users --", 
        '" OR 1=1 --',
    ]
    vulnerable = []

    for payload in sql_payloads:
        # Test URL parameter-based injections
        test_url = f"{url}?q={payload}"
        try:
            response = requests.get(test_url)
            if response.status_code == 200 and "error" in response.text.lower():  # Heuristic: looking for error responses
                vulnerable.append(test_url)
        except Exception as e:
            print(f"Error scanning URL: {test_url} - {e}")

    # Scan POST data as well
    post_data = {'username': "' OR 1=1 --", 'password': "password"}
    try:
        response = requests.post(url, data=post_data)
        if response.status_code == 200 and "error" in response.text.lower():
            vulnerable.append(f"{url} with POST data")
    except Exception as e:
        print(f"Error scanning POST data: {url} - {e}")

    return vulnerable


# Exposed Sensitive Files Detection
def check_sensitive_files(url):
    sensitive_files = [
        '.git', '.env', 'config.php', 'backup.zip', 'db.sql', '.gitmodules', '.swp', '.bak'
    ]
    exposed_files = []

    for file in sensitive_files:
        file_url = f"{url}/{file}"
        try:
            response = requests.get(file_url)
            if response.status_code == 200:
                exposed_files.append(file_url)
        except Exception as e:
            print(f"Error scanning for file: {file_url} - {e}")

    # Check for directory traversal
    traversal_urls = [
        f"{url}/../../{file}" for file in sensitive_files
    ]
    for url in traversal_urls:
        try:
            response = requests.get(url)
            if response.status_code == 200:
                exposed_files.append(url)
        except Exception as e:
            print(f"Error scanning for traversal: {url} - {e}")

    return exposed_files


# Clickjacking Detection
def check_clickjacking(url):
    try:
        response = requests.get(url)
        headers = response.headers

        # Check for X-Frame-Options
        x_frame_option = headers.get("X-Frame-Options", "").lower()
        if x_frame_option != "deny" and x_frame_option != "sameorigin":
            print(f"[!] Vulnerable to Clickjacking: {url} - Missing/Weak X-Frame-Options")

        # Check for Content Security Policy (CSP)
        csp = headers.get("Content-Security-Policy", "")
        if "frame-ancestors" not in csp:
            print(f"[!] Vulnerable to Clickjacking: {url} - Missing frame-ancestors in CSP")

    except Exception as e:
        print(f"Error scanning clickjacking vulnerability: {url} - {e}")


# Main Scanning Function
def scan_website(url):
    print(f"Scanning: {url}")
    
    # Check SQL Injection
    print("[!] Checking for SQL Injection...")
    sql_injections = check_sql_injection(url)
    if sql_injections:
        print(f"[!] Potential SQL Injection vulnerabilities found: {sql_injections}")
    else:
        print("[!] No SQL Injection vulnerabilities found.")

    # Check Sensitive Files
    print("[!] Checking for exposed sensitive files...")
    sensitive_files = check_sensitive_files(url)
    if sensitive_files:
        print(f"[!] Exposed sensitive files found: {sensitive_files}")
    else:
        print("[!] No exposed sensitive files found.")

    # Check Clickjacking
    print("[!] Checking for clickjacking vulnerability...")
    check_clickjacking(url)
    
    print("[!] Scan complete.")


# Example of Running the Scan
if __name__ == "__main__":
    website_url = input("Enter website URL (e.g., https://example.com): ")
    scan_website(website_url)
