from setuptools import setup, find_packages

setup(
    name="obeliskscan",
    version="1.0.0",
    author="Obelisk Team",
    description="A Brutalist-style vulnerability scanner for dependencies and live targets.",
    packages=find_packages(),
    install_requires=[
        "requests>=2.27.0",
        "rich>=12.0.0",
        "fpdf2>=2.7.0",
    ],
    entry_points={
        "console_scripts": [
            "obeliskscan=obeliskscan.cli.run:main",
        ],
    },
    python_requires=">=3.8",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
