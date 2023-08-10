import os
import json
import bcrypt
from time import sleep
from datetime import datetime

from wheezy.web import authorize
from wheezy.security import Principal
from wheezy.http import HTTPCookie
from wheezy.html.utils import escape_html

from main import Users
from handlers import MainHandler
from validation import Validation
from config import options, ticket, roles
from json_validation import validation_func
from models import (
    Login,
    Rights,
    Registration,
    ChangeRights
)

class HomeHandler(MainHandler):
    def get(self):
        if not self.principal:
            return self.render_response("non_authorized_home.html")

        users = Users()
        login = users.get_login(self.principal.id)
        rights = json.loads(users.get_rights(login))
        if tuple(rights) != self.principal.roles:
            return self.redirect_for("auth")
        if self.principal.roles[0] == "":
            return self.render_response(
                "requests.html",
                login=login,
                rights=rights,
                roles=roles,
                req_model=Rights()
            )
        rights = [self.principal.roles][0]
        return self.render_response(
            "authorized_home.html",
            login=login,
            rights=rights,
            roles=roles
        )


class RegisterHandler(MainHandler):
    def get(self):
        if self.principal:
            return self.redirect_for("home")

        return self.render_response(
            "reg_page.html",
            registration=Registration()
        )

    def post(self):
        registration = Registration()
        self.try_update_model(registration)
        login = registration.login
        login_errors = []
        success, error_message = Validation().validate_reg_form(
            login,
            registration.password,
            registration.verify
        )

        if not success:
            for key in error_message:
                login_errors.append(error_message[key])

            self.errors = ({'errors': login_errors})

            return self.render_response(
                "reg_page.html",
                registration=registration
            )

        enc_password = bcrypt.hashpw(
            registration.password.encode(), bcrypt.gensalt()
        )
        
        login = escape_html(login)
        enc_login = ticket.encode(login)

        Users().sign_up(
            login,
            enc_password,
            '[""]'
        )

        self.cookies.append(
            HTTPCookie(
                name="user_login",
                value=enc_login,
                httponly=True,
                options=options,
                max_age=15 * 60
            )
        )

        return self.redirect_for("auth")


class AuthorizationHandler(MainHandler):
    def get(self):
        users = Users()
        try:
            login = ticket.decode(self.request.cookies['user_login'])[0]
            rights = json.loads(users.get_rights(login))
            self.principal = Principal(
                id=str(users.get_user_data(login)["id"]),
                roles=rights
            )
            if rights[0] == '':
                return self.render_response("requests.html")

            return self.redirect_for("home")

        except (TypeError, KeyError):
            return self.redirect_for("home")


class LoginHandler(MainHandler):
    def get(self):
        if self.principal:
            return self.redirect_for("home")

        return self.render_response(
            "login_page.html",
            login_model=Login()
        )

    def post(self):
        login_model = Login()
        self.try_update_model(login_model)
        login = escape_html(login_model.login)
        success, error_message = Validation()\
            .validate_login_form(login, login_model.password)
        if success:
            enc_login = ticket.encode(login)
            self.cookies.append(
                HTTPCookie(
                    name="user_login",
                    value=enc_login,
                    httponly=True,
                    options=options,
                    max_age=15 * 60
                )
            )

            return self.redirect_for("auth")

        else:
            self.errors = ({'errors': error_message})

            return self.render_response(
                "login_page.html",
                login_model=login_model
            )


class SnakeHandler(MainHandler):
    @authorize(roles=("gamer","super"))
    def get(self):
        users = Users()
        login = users.get_login(self.principal.id)

        return self.render_response(
            "snake.html",
            login=login,
            score=users.score_amount(login),
            stats=users.get_high_scores()
        )


class ScoreHandler(MainHandler):
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


class LogoutHandler(MainHandler):
    def get(self):
        self.cookies.append(
            HTTPCookie.delete(
                name="user_login",
                options=options
            )
        )
        del self.principal

        return self.redirect_for('home')


class MyScoresHandler(MainHandler):
    @authorize(roles=("gamer","super"))
    def get(self):
        return self.render_response(
            "scores.html",
            stats=Users().get_stats(str(self.principal.id)))


class GamesDashboardHandler(MainHandler):
    @authorize(roles=("gamer","super"))
    def get(self):
        return self.render_response(
            "game_dashboard.html",
            login=Users().get_login(self.principal.id))


class JsonValidationHandler(MainHandler):
    @authorize(roles=("admin", "super"))
    def get(self):
        return self.render_response("json_val.html")


# class ErrorListHandler(MainHandler):
#     @authorize(roles=("admin","super"))
#     def get(self):
#         pass
        # users = Users()
        # user_id = self.principal.id
        # user_data = users.get_errors(user_id)
        # error_data = []
        # for error in user_data:
        #     error_data.append(error["errors"])
        # return self.render_response("error_list.html", error_data=error_data)


class GetErrorHandler(MainHandler):
    def post(self):
        error_data = {"errors": [], "fixed": []}
        for error in Users().get_errors(self.principal.id):
            error_data["errors"].append(error["errors"])
            error_data["fixed"].append(error["fixed"])

        return self.json_response(error_data)


class UpdateErrorHandler(MainHandler):
    def post(self):
        
        with open("temp/temp.json", "w") as file:
            json.dump(
                json.loads(
                    self.request.files["file"][0].file.read().decode("utf-8")
                ),
                file,
                indent=6
            )
        users = Users()
        user_id = self.principal.id
        fixed = 0
        error_list = validation_func("temp/temp.json")
        user_data = users.get_errors(user_id)
        error_data = {"errors": [], "fixed": []}
        for error in user_data:
            error_data["errors"].append(error["errors"])
            error_data["fixed"].append(error["fixed"])
        for user in user_data:
            if user["errors"] not in error_list:
                fixed = 1
                users.update_errors(user_id, user["errors"], fixed)
            elif user["fixed"]:
                fixed = 0
                users.update_errors(user_id, user["errors"], fixed)
        for error in error_list:
            users.insert_errors(user_id, error, fixed)
        if os.path.exists("temp/temp.json"):
            os.remove("temp/temp.json")

        return self.render_response("error_list.html")


class ChangeRightsHandler(MainHandler):
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
        rights_model = ChangeRights()
        users = Users()
        self.try_update_model(rights_model)
        rights_dict = {}
        old_req = []
        for item in rights_model.rights:            
            item = json.loads(item)
            key = list(item.keys())[0]
            value = list(item.values())[0]
            if key in rights_dict:
                rights_dict[key].append(value)
            else:
                rights_dict[key] = [value]

        usr_data = users.get_no_super_logins()
        login_list = []
        for data in usr_data:
            login_list.append(data["login"])


        for usr in login_list:
            if not usr in rights_dict:
                users.change_roles(usr, '[""]')
                

        for login in rights_dict:
            rights = json.dumps(rights_dict[login])
            users.change_roles(login, rights)

            req = json.loads(users.get_request(login))
            old_req = json.loads(users.get_request(login))

            if len(req) > 0:
                for request in req:
                    if request in rights:
                        old_req.remove(request)
                
                users.post_requests(
                    login=login,
                    request=json.dumps(old_req)
                )


        

        return self.get()


class PostNewHandler(MainHandler):
    def post(self):
        pass
        # rights_model = ChangeRights()
        # self.try_update_model(rights_model)
        # form = self.request.form
        # roles = []
        # users = Users()
        # for htmllogin in form:
        #     login = users.html_decrypt(htmllogin)
        #     roles = form[htmllogin]
        #     users.change_roles(login, json.dumps(roles))

        # return self.json_response({"status": "ok"})


class RequestDelete(MainHandler):
    def post(self):
        form = self.request.form
        users = Users()
        for htmllogin in form:
            login = users.html_decrypt(htmllogin)
            old_req = json.loads(users.get_request(login))
            for i in form[htmllogin]:
                if i in old_req:
                    old_req.remove(i)
                    if len(old_req) == 0:
                        users.set_request_null(login=login)
                    else:
                        users.post_requests(
                            login=login,
                            request=json.dumps(old_req)
                        )

        return self.json_response({"status": "ok"})


class RequestHandler(MainHandler):
    @authorize()
    def get(self):
        users = Users()
        login = users.get_login(self.principal.id)

        return self.render_response(
            "requests.html",
            login=login, 
            rights=json.loads(users.get_rights(login)), 
            roles=roles,
            req_model=Rights()
        )

    def post(self):
        req_model = Rights()
        users = Users()
        self.try_update_model(req_model)
        login = users.get_login(self.principal.id)
        users.post_requests(login, json.dumps(req_model.request))

        return self.render_response(
            "requests.html",
            login=login, 
            rights=json.loads(users.get_rights(login)), 
            roles=roles,
            req_model=req_model
        )