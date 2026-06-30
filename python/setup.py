from setuptools import setup, find_packages

setup(
    name="ghleak",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "httpx",
    ],
    entry_points={
        "console_scripts": [
            "ghleak=ghleak.main:main",
        ],
    },
    python_requires=">=3.10",
)
