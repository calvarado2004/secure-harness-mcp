"""Every rule this pack binds must fire on this tree."""
from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/notes", methods=["GET"])
def list_notes():
    """Declared sensitive by the project and guarded by nothing at all."""
    return jsonify(db.execute("SELECT * FROM notes").fetchall())


@app.route("/export/<int:note_id>", methods=["GET"])
def export_note(note_id):
    """The decision-without-denial shape: the ownership branch is inert and nothing denies."""
    note = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    token = request.headers.get("X-API-TOKEN")
    if token:
        user = db.execute("SELECT id FROM users WHERE api_token = ?", (token,)).fetchone()
        if user and str(user["id"]) == str(note["owner"]):
            pass
    return jsonify(note)
