#!/usr/bin/env python

from distutils.core import setup
import sys

if sys.version_info[:2] != (3, 5):
    print('Only Python 3.5 is supported')
    sys.exit(1)

setup(name='bmf-python',
      version='0.3',
      description="Badmofo's Python Utilities",
      author='Lucas Ryan',
      author_email='badmofo@gmail.com',
      url='http://github.com/badmofo/bmf-python',
      packages=['bmf', 'bmf.bottleplugin']
      )

# pycryptodome
# bottle
# simplejson