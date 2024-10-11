from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="pywhisker",
    version="0.1.0",
    author="Charlie Bromberg & Podalirius",
    author_email="",
    description="Python (re)setter for property msDS-KeyCredentialLink for Shadow Credentials attacks",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ShutdownRepo/pywhisker",
    packages=find_packages(),
    install_requires=[
        "impacket",
        "ldap3",
        "ldapdomaindump",
        "dsinternals",
        "rich",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
    entry_points={
        "console_scripts": [
            "pywhisker=pywhisker.pywhisker:main",
        ],
    },
)