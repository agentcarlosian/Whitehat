"""Owned teaching fixture. Analyze as text; do not expose as a service."""
import pickle
import subprocess


def calculate(expression):
    return eval(expression)


def restore(serialized):
    return pickle.loads(serialized)


def list_project(command):
    return subprocess.run(command, shell=True, check=True)
