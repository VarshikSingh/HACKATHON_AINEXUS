import streamlit as st
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

st.title("SQL Injection Vulnerability Scanner")

url = st.text_input("Enter URL to scan")

scan = st.button("Start Scan")

payloads = [
"'",
"' OR '1'='1",
"' OR '1'='1' --",
"' OR 1=1 #",
"admin' --"
]

error_signatures = [
"SQL syntax",
"mysql_fetch",
"ORA-",
"syntax error",
"mysql",
"warning"
]

def inject_payload(url, param, payload):
    
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    params[param] = payload

    new_query = urlencode(params, doseq=True)

    new_url = urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        new_query,
        parsed.fragment
    ))

    return new_url


if scan:

    if "?" not in url:
        st.error("URL must contain parameters (example: ?id=1)")
    else:

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        st.write("Detected Parameters:", list(params.keys()))

        vulnerable = False

        for param in params:

            for payload in payloads:

                test_url = inject_payload(url, param, payload)

                st.write("Testing:", test_url)

                try:

                    response = requests.get(test_url, timeout=5)

                    for error in error_signatures:

                        if error.lower() in response.text.lower():

                            st.error("SQL Injection Vulnerability Detected")

                            st.write("Parameter:", param)
                            st.write("Payload:", payload)
                            st.write("Tested URL:", test_url)

                            vulnerable = True
                            break

                    if vulnerable:
                        break

                except:
                    st.warning("Request failed")

            if vulnerable:
                break

        if not vulnerable:
            st.success("No SQL Injection vulnerability detected")