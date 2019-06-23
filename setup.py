import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="git-privacy-manager",
    version="0.0.0",
    author="Sergey Kovalev",
    author_email="valor@list.ru",
    description="Store sensitive data in open repositories",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/skvl/git-privacy-manager",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Intended Audience :: End Users/Desktop",
        "Development Status :: 2 - Pre-Alpha",
        "Natural Language :: English",
        "Topic :: Communications :: File Sharing",
    ],
)