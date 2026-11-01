
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED

OUTPUT = Path("stage3_test_archives")
OUTPUT.mkdir(exist_ok=True)

packages = {
    "demo-1.0.0.zip": {
        "version": "1.0.0",
        "setup": """from setuptools import setup

setup(name="demo", version="1.0.0")
""",
    },
    "demo-1.1.0.zip": {
        "version": "1.1.0",
        "setup": """from setuptools import setup

setup(
    name="demo",
    version="1.1.0",
    cmdclass={},
)
""",
    },
}

for archive_name, package in packages.items():
    with ZipFile(OUTPUT / archive_name, "w", ZIP_DEFLATED) as archive:
        archive.writestr(
            "setup.py",
            package["setup"],
        )

        archive.writestr(
            "PKG-INFO",
            f"Metadata-Version: 2.1\nName: demo\nVersion: {package['version']}\n",
        )

        archive.writestr(
            "main.py",
            "def hello():\n    return 'Hello from demo'\n",
        )

    print(f"Created: {OUTPUT / archive_name}")

print("\nBoth Stage 3 test archives are ready.")
