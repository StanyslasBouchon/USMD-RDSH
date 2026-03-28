"""Setup script for the usmd-rdsh (Unified System Management and Deployment) package."""

from setuptools import find_namespace_packages, setup

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

try:
    with open("requirements.txt", "r", encoding="utf-8") as fh:
        requirements = [
            line.strip() for line in fh if line.strip() and not line.startswith("#")
        ]
except FileNotFoundError:
    requirements = []

setup(
    name="usmd-rdsh",
    version="1.0.0",
    author="Devling",
    author_email="contact@devling.fr",
    description="Unified System Management and Deployment for Relative and Dynamic Service Hosting",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/StanyslasBouchon/USMD-RDSH",
    packages=find_namespace_packages(include=["usmd", "usmd.*"]),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.11",
    install_requires=requirements,
    package_data={
        "usmd": ["py.typed"],
    },
)
