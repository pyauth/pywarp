#!/usr/bin/env python

from setuptools import find_packages, setup

setup(
    name="pywarp",
    url="https://github.com/pyauth/pywarp",
    license="Apache Software License",
    author="Andrey Kislyuk",
    author_email="kislyuk@gmail.com",
    description="Python WebAuthn Relying Party library",
    long_description=open("README.rst").read(),
    use_scm_version={
        "write_to": "pywarp/version.py",
    },
    setup_requires=["setuptools_scm >= 3.4.3"],
    install_requires=[
        "pyjwt >= 2.3.0",
        "cbor2 >= 5.2.0, < 6",
        "cryptography >= 3.3.2",
        "requests >= 2.25.1, < 3",
    ],
    extras_require={
        "tests": [
            "flake8",
            "coverage",
            "build",
            "wheel",
            "mypy",
        ],
    },
    packages=find_packages(exclude=["test"]),
    include_package_data=True,
    test_suite="test",
    classifiers=[
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: POSIX",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
)
