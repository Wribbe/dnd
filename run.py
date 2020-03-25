#!/usr/bin/env python

import subprocess
import sys
import os

from pathlib import Path

DIR_VENV = Path("venv")

def call(command):
  if type(command) == str:
    command = command.split(' ')
  return subprocess.call(command)

def venv_py():
  for root, _, files in os.walk(DIR_VENV):
    for file in files:
      if file.startswith('python'):
        return Path(root, file)

def main():

  if not DIR_VENV.is_dir():
    """ Set up virtual environment. """
    PY = sys.executable
    call(f"{PY} -m venv {DIR_VENV}")
    PY = venv_py()
    call(f"{PY} -m pip install --upgrade pip")
    call(f"{PY} -m pip install -r requirements.txt")

  PY = venv_py()
  args = ' '.join(sys.argv[1:])
  call(f"{PY} {Path('dnd', 'main.py')} {args}")

if __name__ == "__main__":
  main()
