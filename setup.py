#!/usr/bin/env python

import os.path

from setuptools import setup

ROOT = os.path.dirname(__file__)

setup(
    version="0.1.1",
    url="https://github.com/nathforge/validatesns",
    name="validatesns",
    description="Validate integrity of Amazon SNS messages",
    long_description=open(os.path.join(ROOT, "README.rst")).read(),
    author="Nathan Reynolds",
    author_email="email@nreynolds.co.uk",
    packages=["validatesns"],
    package_dir={"": os.path.join(ROOT, "src")},
    test_suite="tests",
    install_requires=[
        line.strip()
        for line in open(os.path.join(ROOT, "requirements.txt"))
        if not line.startswith("#")
        and line.strip() != ""
    ],
    tests_require=[
        "mock",
        "oscrypto",
        "six"
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Software Development",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4"
    ]
)
