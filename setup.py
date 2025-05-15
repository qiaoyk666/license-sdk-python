
from setuptools import setup, find_packages

setup(
    name="license-sdk-python",
    version="0.0.8",
    keywords=("pip", "license", "sdk"),
    description="license sdk python",
    license="MIT Licence",

    url="https://github.com/qiaoyk666/license-sdk-python.git",
    author="qiao",
    author_email="979146919@qq.com",

    packages=find_packages(),
    install_requires=[
        "requests",
        "cryptography",
        "websocket-client",
        "pycryptodome"
    ],
    include_package_data=True,
    platforms="any"
)