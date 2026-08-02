"""Negative control: the paired conformant fixture.

Identical to the positive control except that `Widgets.put` now carries the same
`admin_permission.require` its POST and DELETE siblings carry. No mutating verb departs from the
resource's convention, so the sibling rule must stay silent, and with no `protected_data` policy
the inherited read rule must stay silent too. `Public` (no guard) and `Validated` (a validator,
not a guard) exist to prove neither is mistaken for the missing-guard case. Parsed, not executed.
"""
from flask import Blueprint
from flask_restful import Api

mod = Blueprint("mod", __name__, url_prefix="/api/1")
api = Api(mod)


class Widgets(Resource):
    @admin_permission.require(http_exception=403)
    def post(self, widget_id): ...
    @admin_permission.require(http_exception=403)
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
