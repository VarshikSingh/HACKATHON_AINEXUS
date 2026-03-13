from urllib.parse import urljoin
import requests
from bs4 import BeautifulSoup
import html

# unique payload for testing
payload = "<script>alert('XSS_TEST')</script>"


def submit_form(form, url, payload):

    action = form.attrs.get("action")
    method = form.attrs.get("method", "get").lower()

    target_url = urljoin(url, action)

    inputs = form.find_all("input")

    data = {}

    for input_tag in inputs:
        name = input_tag.attrs.get("name")

        if name:
            data[name] = payload

    if method == "post":
        return requests.post(target_url, data=data)

    else:
        return requests.get(target_url, params=data)


# get target URL
url = input("Enter url: ")

try:

    response = requests.get(url, timeout=5)

    soup = BeautifulSoup(response.text, "html.parser")

    forms = soup.find_all("form")

    print(f"[+] Found {len(forms)} forms")

    for form in forms:

        action = form.attrs.get("action")

        print(f"\n[+] Testing form: {action}")

        response = submit_form(form, url, payload)

        # detection logic
        if payload in response.text and html.escape(payload) not in response.text:

            print("[!] Possible Reflected XSS Detected!")
            print("Payload:", payload)
            print("Form action:", action)

        else:
            print("[-] No XSS detected")

except requests.exceptions.RequestException as e:

    print("Error connecting to site:", e)