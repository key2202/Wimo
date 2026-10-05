from setuptools import setup, find_packages

setup(
    name="wimo",
    version="1.0.0",
    description="WiMO - Wireless Monitor & Orchestrator (pink CLI)",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "scapy>=2.5.0",
        "rich>=13.7.0",
        "prompt_toolkit>=3.0.43",
        "mac-vendor-lookup>=0.1.12",
        "psutil>=5.9.0",
        "pyroute2>=0.7.0",
    ],
    entry_points={
        "console_scripts": ["wimo=wimo.__main__:main"],
    },
)
