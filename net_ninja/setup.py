from setuptools import setup, find_packages

setup(
    name="net_ninja",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        'pandas',
        'numpy',
        'requests',
        'scipy'
    ],
    author="kanishk thamman",
    author_email="kanishk.thamman@pm.me",
    description="A package to generate enhanced network features for attack detection",
    long_description=open('README.md').read(),
    long_description_content_type="text/markdown",
    url="",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)