import sys
import subprocess
from setuptools import setup, find_packages

# Ensure UTF-8 for Windows console
_enc = (getattr(sys.stdout, "encoding", None) or "").lower()
if sys.platform.startswith("win") and _enc != "utf-8":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# ANSI Colors for Setup
PURPLE = "\033[95m"
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"
BOLD = "\033[1m"

BANNER = f"""
{PURPLE}{BOLD}▄███▄   ▄▀▀▄ █▀▀▄ █▀▀▀ █    █ ▄▀▀▀ █ ▄▀
█ ██ █  █  █ █▀▀▄ █▀▀  █    █ ▀▀▀█ █▀▄ 
▀███▀    ▀▀  ▀▀▀  ▀▀▀▀ ▀▀▀▀ ▀ ▀▀▀  ▀  ▀{RESET}
{CYAN}            S  C  A  N  N  E  R{RESET}
"""

def run_interactive():
    print(BANNER)
    print(f"{BOLD}OBELISK SCANNER - Setup Manager{RESET}")
    print("-" * 50)
    print(f"[{GREEN}1{RESET}] {BOLD}Standard Installation{RESET}")
    print(f"    Installs OBELISK SCANNER to your sys-path.")
    print(f"[{GREEN}2{RESET}] {BOLD}Development Mode{RESET}")
    print(f"    Link this folder for active development.")
    print(f"[{GREEN}3{RESET}] {BOLD}Check Dependencies{RESET}")
    print(f"    Ensures all requirements are satisfied.")
    print(f"[{GREEN}4{RESET}] {BOLD}Uninstall{RESET}")
    print(f"    Removes the tool from your system.")
    print(f"[{GREEN}5{RESET}] {BOLD}Exit{RESET}")
    print("-" * 50)
    
    try:
        choice = input(f"{YELLOW}Select an operation [1-5]: {RESET}").strip()
    except EOFError:
        return

    if choice == '1':
        print(f"{CYAN}Initializing Standard Install...{RESET}")
        subprocess.run([sys.executable, "-m", "pip", "install", "."])
    elif choice == '2':
        print(f"{CYAN}Initializing Development Install...{RESET}")
        subprocess.run([sys.executable, "-m", "pip", "install", "-e", "."])
    elif choice == '3':
        print(f"{CYAN}Checking Requirements...{RESET}")
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
    elif choice == '4':
        print(f"{CYAN}Uninstalling OBELISK SCANNER...{RESET}")
        subprocess.run([sys.executable, "-m", "pip", "uninstall", "obeliskscan", "-y"])
    elif choice == '5':
        sys.exit(0)
    else:
        print(f"{YELLOW}Invalid choice. Exiting.{RESET}")

if __name__ == "__main__":
    if len(sys.argv) == 1:
        run_interactive()
        sys.exit(0)

# Standard Setuptools Metadata
setup(
    name="obelisk",
    version="1.0.0",
    author="Obelisk Team",
    description="A Brutalist-style vulnerability scanner for dependencies and live targets.",
    packages=find_packages(),
    install_requires=[
        "requests>=2.27.0",
        "rich>=12.0.0",
        "fpdf2>=2.7.0",
        "toml>=0.10.2",
    ],
    entry_points={
        "console_scripts": [
            "obelisk=obeliskscan.cli.run:main",
        ],
    },
    python_requires=">=3.8",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
