#!/usr/bin/env python2

__author__ = "Gary Choi"
__project__= "Graduate Research Project"
__name__="WAAT"

import os
import sys
from subprocess import run, PIPE

res = run('apt-cache policy aircrack-ng', shell=True, stdout=PIPE, stderr=PIPE, check=True)
print(res.returncode, res.stdout, res.stderr)