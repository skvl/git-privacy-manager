Git Privacy Manager: GPM
========================

|build-status| |sonarcloud| |lgtm| |codecov| |docs|

GPM lets you to manage files, synchronize it between multiple devices
and securely backup it to multiple repositories.

Futures
-------

* File management
* Extensible meta-data for each file
* Hierarchical tags for each file
* Peer-to-peer synchronization
* Partial synchronization
* Encrypted backups to multiple repositories
* Specifiyng repositories per file
* Cross-platform GUI

Roadmap
-------

* v0.1.0 - encrypted backups for local file system with CLI
* v0.2.0 - conflict resolution while synchronization
* v0.3.0 - partial synchronization
* v0.4.0 - hierarchical tags management
* v0.5.0 - user provided meta-data per file
* v1.0.0 - basic cross-platform GUI
* v1.1.0 - peer-to-peer synchronization
* v1.2.0 - pluggable architecture

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
