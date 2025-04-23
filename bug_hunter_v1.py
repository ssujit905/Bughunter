import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import csv
from datetime import datetime

def fetch_links(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        links = [urljoin(url, link.get('href')) for link in soup.find_all('a', href=True)]
        return links
    except Exception as e:
        print(f"[!] Failed to fetch links from {url}: {e}")
        return []

def check_link(link):
    try:
        response = requests.head(link, allow_redirects=True, timeout=5)
        return response.status_code < 400
    except:
        return False

def check_security_headers(url):
    missing_headers = []
    important_headers = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "Strict-Transport-Security",
        "X-Content-Type-Options"
    ]
    clickjacking_vulnerable = False

    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, timeout=10)

        for header in important_headers:
            if header not in response.headers:
                missing_headers.append(header)

        if "X-Frame-Options" not in response.headers and \
           "Content-Security-Policy" not in response.headers:
            clickjacking_vulnerable = True

    except requests.exceptions.RequestException as e:
        print(f"[!] Failed to check headers for {url}: {e}")

    return missing_headers, clickjacking_vulnerable

def check_open_redirect(url):
    open_redirects = []
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, timeout=10)
        
        # Look for URL parameters that could be open redirects
        if "url=" in response.url:
            parsed_url = urlparse(response.url)
            redirect_url = parsed_url.query.split('=')[1]
            # Check if it is an external domain (not the same domain)
            if urlparse(redirect_url).netloc and urlparse(redirect_url).netloc != urlparse(url).netloc:
                open_redirects.append(redirect_url)
    except requests.exceptions.RequestException as e:
        print(f"[!] Failed to check for open redirects for {url}: {e}")

    return open_redirects

def scan_site(url):
    print(f"\nScanning: {url}")
    links = fetch_links(url)
    broken = [link for link in links if not check_link(link)]

    missing_headers, clickjacking_vulnerable = check_security_headers(url)
    open_redirects = check_open_redirect(url)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    txt_report = f"bug_report_{timestamp}.txt"
    csv_report = f"bug_report_{timestamp}.csv"

    # Save TXT Report
    with open(txt_report, 'w') as f:
        f.write(f"Bug Report for {url}\n")
        f.write("="*50 + "\n\n")
        f.write("Broken Links:\n")
        for link in broken:
            f.write(link + "\n")

        f.write(f"\nSecurity Headers Missing: {', '.join(missing_headers) if missing_headers else 'None'}\n")
        f.write(f"Clickjacking Vulnerable: {'Yes' if clickjacking_vulnerable else 'No'}\n")

        f.write(f"\nOpen Redirects Found: {', '.join(open_redirects) if open_redirects else 'None'}\n")

    # Save CSV Report
    with open(csv_report, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Issue Type', 'Details'])
        for link in broken:
            writer.writerow(['Broken Link', link])
        for header in missing_headers:
            writer.writerow(['Missing Header', header])
        writer.writerow(['Clickjacking Vulnerable', 'Yes' if clickjacking_vulnerable else 'No'])
        for redirect in open_redirects:
            writer.writerow(['Open Redirect', redirect])

    print(f"\nReports saved: {txt_report} and {csv_report}")
    print(f"{len(broken)} broken links found.")
    if missing_headers:
        print(f"[!] {len(missing_headers)} security headers missing.")
    else:
        print("[+] All important security headers are present!")
    if clickjacking_vulnerable:
        print("[!] Site may be vulnerable to Clickjacking!")
    else:
        print("[+] Clickjacking protection is in place.")
    if open_redirects:
        print(f"[!] Found open redirect(s): {', '.join(open_redirects)}")
    else:
        print("[+] No open redirects detected.")

if __name__ == "__main__":
    url = input("Enter website URL (e.g. https://example.com): ").strip()
    scan_site(url)
