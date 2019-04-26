from setuptools import setup
from os import path
this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='appsync-client',
    version='0.0.12',
    license='TBD',
    author='Vasudevan Palani',
    author_email='vasudevan.palani@gmail.com',
    url='https://github.com/vasudevan-palani/appsync-client',
    long_description=long_description,
    long_description_content_type='text/markdown',
    packages=['appsyncclient'],
    include_package_data=True,
    description="Appsync python client for consuming the graphql endpoint",
)
