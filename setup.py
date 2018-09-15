"""
Flask-TokenSchema
-----------------
"""
import re
from setuptools import setup, find_packages

with open('token_auth/__init__.py', 'r') as f:
    version = re.search(r'^__version__\s*=\s*[\'"]([^\'"]*)[\'"]', f.read(),
                        re.MULTILINE).group(1)

setup(
    name='Flask-TokenSchema',
    version=version,
    url='http://github.com/alvie97/flask-tokenschema',
    license='MIT',
    author='Alfredo Viera',
    description='Token schema using access token (jwt) and refresh token',
    py_modules=['token_auth'],
    install_requires=['Flask', 'PyJwt'],
    packages=["token_schema"],
    zip_safe=False,
    platforms='any',
    test_suite="tests")
