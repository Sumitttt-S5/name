import subprocess
import os

def run_command(user_input):
    subprocess.run(user_input, shell=True)

def access_environment():
    token = os.environ.get("API_TOKEN")
    return token

if __name__ == "__main__":
    run_command("echo Supply Chain Guardian test")
    access_environment()
