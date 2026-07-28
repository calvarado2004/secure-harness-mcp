"""Positive control for the commodity Python lanes.

One instance of each defect class the pattern lanes are supposed to see. Not every rule in
the pack is represented -- the dataflow rules (py/*) need CodeQL and a whole application to
have anything to flow through, and claiming otherwise here would be the kind of overclaim
this project keeps finding in its own instruments. What this file proves is narrower and
still worth proving: that bandit is actually running and reporting, so that a zero from it
means "bandit found nothing" rather than "bandit did not run".
"""
import hashlib
import pickle
import subprocess
import yaml

API_TOKEN = "sk-live-2f8e11c4a90b4f77"          # B105 hardcoded secret


def check(pw):
    return hashlib.md5(pw.encode()).hexdigest()  # B324 weak hash for a security decision


def load(blob):
    return pickle.loads(blob)                    # B301 unpickling untrusted data


def parse(doc):
    return yaml.load(doc)                        # B506 unsafe yaml load


def compute(expr):
    return eval(expr)                            # B307 eval on input


def run(name):
    return subprocess.call("ls " + name, shell=True)   # B602 shell injection


def find(conn, term):
    return conn.execute("SELECT * FROM notes WHERE body LIKE '%" + term + "%'")  # B608


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)          # B104 bind-all + B201 flask debug
