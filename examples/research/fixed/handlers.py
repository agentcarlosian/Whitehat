"""Fixed twin for the owned teaching fixture."""
import ast
import json
import subprocess


def calculate(expression):
    return ast.literal_eval(expression)


def restore(serialized):
    return json.loads(serialized)


def list_project(directory):
    return subprocess.run(["git", "-C", directory, "status", "--short"], shell=False, check=True)
