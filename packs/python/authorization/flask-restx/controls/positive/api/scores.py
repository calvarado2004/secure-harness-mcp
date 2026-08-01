"""The deviating handler: identity read, other guards present, the account guard missing."""
from flask_restx import Namespace, Resource

scores_namespace = Namespace("scores")


@scores_namespace.route("/<board_id>/standings")
class Standings(Resource):
    @check_board_visibility
    @during_event_only
    def get(self, board_id):
        # Same disclosure as the guarded handlers, without the guard they carry.
        return {"data": Roster.query.add_columns(Person.name.label("account_name")).all()}


@scores_namespace.route("/recount")
class Recount(Resource):
    # A WRITE that touches the same table. A visibility guard controls disclosure, so this
    # must NOT be flagged; if it is, the lane is spending repair rounds on non-disclosures.
    @authed_only
    def post(self):
        return {"data": Roster.query.add_columns(Person.name.label("account_name")).all()}


@scores_namespace.route("/audit")
class Audit(Resource):
    # Administrators already see everything: the stronger guard subsumes the weaker one.
    @admins_only
    def get(self):
        return {"data": Roster.query.add_columns(Person.name.label("account_name")).all()}
