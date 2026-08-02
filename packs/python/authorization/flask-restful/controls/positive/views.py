"""Positive control for authz/mutation-guard-weaker-than-siblings.

`admin_permission.require` is the project's access convention: three resources carry it, so it
clears min_carriers. `Widgets` mounts POST/PUT/DELETE at one path; POST and DELETE carry the
guard and PUT does not — the exact shape of GHSA-x3vf-mgxj-7785. The lane must name Widgets.PUT
and ONLY it. `Public` establishes no guard locally (silent). `Validated` shares a request-body
validator across two mutating siblings, which is NOT an access guard and must not be mistaken
for one. This is parsed, never executed, so the undefined names are deliberate.
"""
from flask import Blueprint
from flask_restful import Api

mod = Blueprint("mod", __name__, url_prefix="/api/1")
api = Api(mod)


class Widgets(Resource):
    @admin_permission.require(http_exception=403)
    def post(self, widget_id): ...
    def put(self, widget_id): ...
    @admin_permission.require(http_exception=403)
    def delete(self, widget_id): ...
    def get(self, widget_id): ...


class Gadgets(Resource):
    @admin_permission.require(http_exception=403)
    def post(self): ...
    @admin_permission.require(http_exception=403)
    def delete(self): ...


class Public(Resource):
    def post(self): ...
    def put(self): ...
    def delete(self): ...


class Validated(Resource):
    @validate_schema(gizmo_input, gizmo_output)
    def post(self, gizmo_id): ...
    @validate_schema(gizmo_input, gizmo_output)
    def put(self, gizmo_id): ...
    def delete(self, gizmo_id): ...


api.add_resource(Widgets, "/widgets/<int:widget_id>")
api.add_resource(Gadgets, "/gadgets")
api.add_resource(Public, "/public")
api.add_resource(Validated, "/gizmos/<int:gizmo_id>")
