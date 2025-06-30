from setuptools import setup

setup(
    name="findmeaccess",
    version="3.0",
    install_requires=[ "tabulate", "termcolor", "requests", "lxml" ],
    entry_points={ "console_scripts": [ "findmeaccess=findmeaccess:main" ] }
)
