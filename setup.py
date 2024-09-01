from setuptools import setup, find_packages

setup(
    name="pywhisker",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "setuptools",
        "impacket",
        "cryptography",
        "six",
        "pyasn1",
        "ldap3",
        'pyOpenSSL~=22.1.0',
        "ldapdomaindump",
        "rich",
        "dsinternals",
    ],
    entry_points={
        "console_scripts": [
            "pywhisker=pywhisker.pywhisker:main",
        ],
    },
    author="ShutdownRepo",
    description="Python version of the C# tool for Shadow Credentials attacks",
    url="https://github.com/ShutdownRepo/pywhisker",
)
