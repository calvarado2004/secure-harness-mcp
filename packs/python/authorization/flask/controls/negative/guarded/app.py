"""Correct implementations that earlier versions of this lane reported as defects.

Each function here is a spelling of a guard that a naive matcher misses, and every one of
them cost this project a false positive before it was covered.
"""
from flask import Flask, g, jsonify, request

app = Flask(__name__)


@app.route("/admin/users", methods=["GET"])
@require_role("admin")
def admin_list_users():
    """A decorator FACTORY is still a guard."""
    return jsonify(db.execute("SELECT id, username FROM users").fetchall())


@app.route("/admin/backup", methods=["GET"])
def admin_backup():
    """A guard CALLED on the first line is still a guard."""
    denied = require_admin()
    if denied:
        return denied
    return jsonify({"backup": "ok"})


@app.route("/notes", methods=["GET"])
def search_notes():
    """A PRIVATE helper is still a guard, and scoping by the caller is authorization."""
    user = _get_current_user()
    if user is None:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(db.execute("SELECT * FROM notes WHERE owner = ?", (user["id"],)).fetchall())


@app.route("/notes", methods=["POST"])
@token_required
def create_note(user):
    """A decorator-INJECTED principal, used to own the row, is authorization."""
    data = request.get_json()
    db.execute("INSERT INTO notes (owner, title) VALUES (?, ?)",
               (user["username"], data["title"]))
    return jsonify({"created": True}), 201


@app.route("/notes/<int:note_id>", methods=["GET"])
@login_required
def read_note(note_id):
    """An ownership branch that DENIES on the failing path is the fix, not the defect."""
    note = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    if str(note["owner"]) != str(g.user["id"]):
        return jsonify({"error": "not found"}), 404
    return jsonify(note)


@app.route("/login", methods=["POST"])
def login():
    """A declared-public route is a signed decision, not an omission."""
    return jsonify({"token": issue_token(request.get_json())})
