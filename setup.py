from setuptools import setup

setup(
    name="findmeaccess",
    version="3.3.0",
    install_requires=[ "tabulate", "termcolor", "requests[socks]", "lxml" ],
    entry_points={ "console_scripts": [ "findmeaccess=findmeaccess:main" ] }
)
