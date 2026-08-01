# The mount, so the lane reports a path a caller could actually reach.
from flask import Blueprint
from flask_restx import Api

api = Blueprint("api", __name__, url_prefix="/api/v1")
CTF_API = Api(api)
CTF_API.add_namespace(scores_namespace, "/scores")
CTF_API.add_namespace(people_namespace, "/people")
