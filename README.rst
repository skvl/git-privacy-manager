Git Privacy Manager: GPM
========================

|build-status| |sonarcloud| |lgtm| |codecov| |docs|

GPM lets you to store sensitive information in open repositories like GitHub.

Futures
-------

* Encrypts files with GPG
* Stores meta-data to avoid encrypting or decrypting unchanged files
* Stores encrypted blobs in subdirectory
* Follows `Semantic Versioning 2.0.0 <https://semver.org/>`_

Dependencies
------------

* `GnuPG <https://gnupg.org/>`_

Building
--------

.. code-block:: bash

    python3 setup.py sdist bdist_wheel

Installing
----------

.. code-block:: bash

    pip install dist/git_privacy_manager-0.0.1-py3-none-any.whl

Usage
-----

Encrypt current directory
^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

    gpm encrypt

Decrypt current directory
^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

    gpm decrypt

.. |build-status| image:: https://travis-ci.org/skvl/git-privacy-manager.svg?branch=master
    :alt: Build Status
    :scale: 100%
    :target: https://travis-ci.org/skvl/git-privacy-manager

.. |sonarcloud| image:: https://sonarcloud.io/api/project_badges/measure?project=skvl_git-privacy-manager&metric=alert_status
    :alt: Quality Gate Status
    :scale: 100%
    :target: https://sonarcloud.io/dashboard?id=skvl_git-privacy-manager

.. |lgtm| image:: https://img.shields.io/lgtm/alerts/g/skvl/git-privacy-manager.svg?logo=lgtm&logoWidth=18
    :alt: Total alerts
    :scale: 100%
    :target: https://lgtm.com/projects/g/skvl/git-privacy-manager/alerts/

.. |codecov| image:: https://codecov.io/gh/skvl/git-privacy-manager/branch/master/graph/badge.svg
    :alt: Codecov
    :scale: 100%
    :target: https://codecov.io/gh/skvl/git-privacy-manager


.. |docs| image:: https://readthedocs.org/projects/git-privacy-manager/badge/?version=latest
    :alt: Documentation Status
    :scale: 100%
    :target: https://git-privacy-manager.readthedocs.io/en/latest/?badge=latest
