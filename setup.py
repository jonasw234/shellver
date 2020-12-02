import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="shellver",
    version="2.0.0",
    author="0xR00T, Jonas A. Wendorf",
    description="Reverse Shell Cheat Sheet Tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/jonasw234/shellver",
    packages=setuptools.find_packages(),
    install_requires=["docopt", "netifaces"],
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: Linux",
    ],
    python_requires=">=3.7",
    entry_points={
        "console_scripts": ["shellver=shellver.shellver:main"],
    },
)
