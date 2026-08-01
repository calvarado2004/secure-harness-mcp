"""Three handlers establish the convention; the fourth omits it. That is the defect."""
from flask_restx import Namespace, Resource

people_namespace = Namespace("people")


def list_people_with_names():
    # Selects the identifying attribute, which is what the guard exists to control.
    return Roster.query.add_columns(Person.name.label("account_name")).all()


@people_namespace.route("")
class PeopleList(Resource):
    @check_account_visibility
    def get(self):
        return {"data": list_people_with_names()}


@people_namespace.route("/<person_id>")
class PersonDetail(Resource):
    @check_account_visibility
    def get(self, person_id):
        return {"data": list_people_with_names()}


@people_namespace.route("/search")
class PeopleSearch(Resource):
    @check_account_visibility
    def get(self):
        return {"data": list_people_with_names()}
