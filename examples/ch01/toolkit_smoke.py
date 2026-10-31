#!/usr/bin/env python3
"""Smoke-test the ctfkit skeleton: import it and print its version.

If this runs, your virtualenv is set up and ``pip install -e .`` worked.
The modules listed below are added one chapter at a time; right now only the
package itself exists.
"""
import ctfkit

print("ctfkit version:", ctfkit.__version__)
print("package file:", ctfkit.__name__)
