import requests
import sys

# headers_urls = ["https://e3.pncie.com", "https://e1.pncie.com", "https://e2.pncie.com", "https://csaa-insurance.aaa.com", "https://www.google.com", "https://www.twitter.com", "https://www.facebook.com"]
header_url = sys.argv[1]
header_url = "https://" + header_url
found_headers = 0
not_found_headers = 0
headers_list = ["X-Frame-Options",
                "Content-Security-Policy",
                "X-Content-Type-Options",
                "Cache-Control",
                "X-XSS-Protection",
                "Server",
                "Referrer-Policy",
                "Public-Key-Pins",
                "Strict-Transport-Policy"]


# for header_url in headers_urls:
request_headers = requests.request("GET", header_url, verify=False).headers
# print("\n" + header_url)

for header in headers_list:
    try:
        print(header + " " + request_headers[header])
        found_headers += 1
    except:
        print(header + " header not found")
        not_found_headers += 1

print("Headers NOT Found: " + str(not_found_headers))