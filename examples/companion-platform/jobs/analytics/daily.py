import requests


def export(rows):
    requests.post("https://analytics.internal.example/ingest", json=rows, verify=False, timeout=30)
