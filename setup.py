import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="git-privacy-manager",
    # Follows semver 2.0
    version="0.0.0",
    author="Sergey Kovalev",
    author_email="valor@list.ru",
    description="Store sensitive data in open repositories",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/skvl/git-privacy-manager",
    project_urls = {
        'Source' : 'https://github.com/skvl/git-privacy-manager',
        'Tracker': 'https://github.com/skvl/git-privacy-manager/issues'
    },
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
    python_requires='~=3.7',
    install_requires = [ 'python-gnupg >= 0.4.4, < 0.5.0' ],
    entry_points = {
        'console_scripts': ['gpm=git_privacy_manager.command_line:main'],
    },
    test_suite = 'git_privacy_manager.tests',
)
