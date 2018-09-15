"""
token-schema
"""
import re
from setuptools import setup, find_packages

with open('token_auth/__init__.py', 'r') as f:
    version = re.search(r'^__version__\s*=\s*[\'"]([^\'"]*)[\'"]', f.read(),
                        re.MULTILINE).group(1)

setup(
    name='Token-Auth',
    version=version,
    url='http://github.com/alvie97/token-auth',
    license='MIT',
    author='Alfredo Viera',
    description=' Token auth schema using access token (jwt) and refresh token',
    py_modules=['token_auth'],
    install_requires=['Flask', 'PyJwt'],
    packages=["token_auth"]
    test_suite="tests")
