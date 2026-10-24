import httpx
import requests
import ssl


def call(url, payload):
    # ruleid: ceg.tls-verification-disabled
    requests.post(url, json=payload, verify=False)
    # ruleid: ceg.tls-verification-disabled
    client = httpx.Client(verify=False)
    # ruleid: ceg.tls-verification-disabled
    ctx = ssl._create_unverified_context()
    # ok: ceg.tls-verification-disabled
    requests.post(url, json=payload, timeout=10)
    # ok: ceg.tls-verification-disabled
    httpx.Client(verify="/etc/ssl/internal-ca.pem")


def session_level():
    s = requests.Session()
    # ruleid: ceg.tls-verification-disabled
    s.verify = False
    # ok: ceg.tls-verification-disabled
    s.verify = "/etc/ssl/internal-ca.pem"
