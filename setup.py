import setuptools

with open('README.md', 'r') as f:
    long_description = f.read()

setuptools.setup(
    name='python-coinage',
    version='1.0.0',
    author='Francisco Altoe',
    author_email='franciscoda@outlook.com',
    description='Cryptocurrency address validation module',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/FranciscoDA/coinage.git',
    packages=setuptools.find_packages(),
    classifiers=[],
    install_requires=['base58check', 'pysha3'],
    python_requires='>=3.7',
)
