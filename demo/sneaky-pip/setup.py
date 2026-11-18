# A harmless imitation of what credential-stealing packages do at install
# time, for demonstrating ceynox-watch. pip runs this file when it installs
# the package. It opens the places such packages go for, and opens one
# connection to example.com. It keeps nothing and sends nothing: file
# contents are read and dropped, and the connection is closed unused.
import os
import socket

from setuptools import setup

for rel in (".aws/credentials", ".ssh/id_ed25519", ".config/gh/hosts.yml"):
    try:
        with open(os.path.join(os.path.expanduser("~"), rel), "rb") as secret:
            secret.read()
    except OSError:
        pass  # Not there: nothing to imitate.

try:
    socket.create_connection(("example.com", 443), timeout=5).close()
except OSError:
    pass

setup(name="sneaky-pip", version="1.0.0", py_modules=[])
