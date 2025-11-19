#!/usr/bin/env python
"""Setup script for VigilantEye threat intelligence tool."""

from setuptools import setup, find_packages

setup(
    name="vigilanteye",
    version="1.0.0",
    description="Terminal-based threat intelligence aggregator",
    author="VigilantEye",
    python_requires=">=3.9",
    packages=find_packages(),
    install_requires=[
        "aiohttp>=3.8.0",
        "requests>=2.28.0",
        "rich>=13.0.0",
        "python-dotenv>=1.0.0",
        "python-whois>=0.7",
        "nest_asyncio>=1.5.0",
    ],
    entry_points={
        "console_scripts": [
            "vigilanteye=cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
    ],
)
