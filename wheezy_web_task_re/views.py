import json
# import numpy
from datetime import datetime

from wheezy.web import authorize
# from wheezy.http import HTTPCookie
# from wheezy.html.utils import escape_html
from wheezy.web.handlers import BaseHandler

from handlers import MainHandler
from auth import Authorization
from config import roles
from main import Users, Main
from models import (
    Login,
    Rights,
    Registration,
    ChangeRights
)

class HomeHandler(BaseHandler):
    def get(self):
        if not self.principal:
            return self.render_response("non_authorized_home.html")

        users = Users()
        id = self.principal.id
        login = users.get_login(id)
        rights = json.loads(users.get_rights(login))
        params = {
            "template_name": "authorized_home.html",
            "login": login,
            "rights": rights,
            "roles": roles
        }
        if tuple(rights) != self.principal.roles:
            self.principal = Authorization().authorization(id=id, rights=rights)
        if self.principal.roles[0] == "":
            return self.redirect_for("requests")

        return self.render_response(**params)


class RegisterHandler(MainHandler):
    def get(self):
        if self.principal:
            return self.redirect_for("home")

        return self.render_response(
            "reg_page.html",
            model=Registration()
        )

    def post(self):
        model = Registration()
        self.try_update_model(model)
        valid_result = Authorization().validate_reg_form(
            model.login,
            model.password,
            model.verify,
        )

        return self.authorize_model(
            model,
            "reg_page.html",
            valid_result
        )

class LoginHandler(MainHandler):
    def get(self):
        if self.principal:
            return self.redirect_for("home")

        return self.render_response(
            "login_page.html",
            model=Login()
        )

    def post(self):
        model = Login()
        self.try_update_model(model)
        valid_result = Authorization().validate_login_form(
            model.login,
            model.password
        )

        return self.authorize_model(
            model,
            "login_page.html",
            valid_result
        )
        

class SnakeHandler(BaseHandler):
    @authorize(roles=("gamer", "super"))
    def get(self):
        users = Users()
        login = users.get_login(self.principal.id)

        return self.render_response(
            "snake.html",
            login=login,
            score=users.score_amount(login),
            stats=users.get_high_scores()
        )

    def post(self):
        user_id = self.principal.id
        users = Users()
        users.score_insert(
            str(user_id),
            int(self.request.form["score"][0]),
            datetime.now().strftime("%d/%m/%Y %H:%M")
        )
        users.high_score_update(
            int(self.request.form["highscore"][0]),
            user_id
        )


class LogoutHandler(BaseHandler):
    def get(self):
        del self.principal
        return self.redirect_for('home')


class MyScoresHandler(BaseHandler):
    @authorize(roles=("gamer","super"))
    def get(self):
        return self.render_response(
            "scores.html",
            stats=Users().get_stats(str(self.principal.id))
        )


class GamesDashboardHandler(BaseHandler):
    @authorize(roles=("gamer","super"))
    def get(self):
        return self.render_response(
            "game_dashboard.html",
            login=Users().get_login(self.principal.id)
        )


class JsonValidationHandler(BaseHandler):
    @authorize(roles=("admin", "super"))
    def get(self):
        return self.render_response("json_val.html")


class GetErrorHandler(BaseHandler):
    def post(self):
        error_data = {"errors": [], "fixed": []}
        for error in Users().get_errors(self.principal.id):
            error_data["errors"].append(error["errors"])
            error_data["fixed"].append(error["fixed"])

        return self.json_response(error_data)


class UpdateErrorHandler(BaseHandler):
    def post(self):
        with open("temp/temp.json", "w") as file:
            json.dump(
                json.loads(
                    self.request.files["file"][0].file.read().decode("utf-8")
                ),
                file
            )
        Main().updateErrors(user_id=self.principal.id)

        return self.render_response("error_list.html")


class ChangeRightsHandler(BaseHandler):
    @authorize(roles=("super",))
    def get(self):
        users = Users()
        logins = []
        requests_list = []
        right_list = []

        for request in users.get_all_requests():
            requests_list.append(json.loads(request["request"]))

        for user in users.get_all_rights():
            right_list.append(json.loads(user["rights"]))
            logins.append(user["login"])

        return self.render_response(
            "change_rights.html",
            right=right_list, 
            login=logins,
            requests=requests_list,
            roles=roles,
            rights_model=ChangeRights()
        )

    def post(self):
        try:    
            if deleted_login:=self.request.form["login"][0]:
                users = Users()
                try:
                    users.delete_user(users.get_user_data(deleted_login)["id"])
                except TypeError:
                    return self.get()
        except KeyError:
            model = ChangeRights()
            self.try_update_model(model)
            Main().changeRights(model)

        return self.get()


class RequestHandler(BaseHandler):
    @authorize()
    def get(self):
        users = Users()
        login = users.get_login(self.principal.id)
        return self.render_response(
            "requests.html",
            login=login, 
            rights=json.loads(users.get_rights(login)), 
            roles=roles,
            model=Rights()
        )

    def post(self):
        model = Rights()
        users = Users()
        self.try_update_model(model)
        login = users.get_login(self.principal.id)
        users.post_requests(login, json.dumps(model.request))

        return self.get()