from setuptools import setup, find_packages

setup(
    name="vigilanteye",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "rich",
        "aiohttp",
        "requests",
        "python-dotenv",
        "python-whois",
        "nest_asyncio",
    ],
    entry_points={
        "console_scripts": [
            "vigilanteye=core.runner:main",
        ],
    },
    author="grandeemir",
    description="VigilantEye - Threat Intelligence Aggregator",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/grandeemir/VigilantEye",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
)