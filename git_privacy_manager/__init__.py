"""
Git Privacy Manager
===================

Git Privacy Manager is a simple Python utility which encrypts files from
working directory with GnuPG into separate folder. This allows to
synchronize files across open clouds. The encrypted blobs get random names
thus avoiding data loss.

Modules
=======

gpm : The core module

:copyright: © 2019 by the Sergey Kovalev
:license: GNU General Public License v3 (GPLv3), see LICENSE
"""

from .gpm import GPM
from .__about__ import __project__, __author__, __version__, __licence__

__all__ = ['gpm']
