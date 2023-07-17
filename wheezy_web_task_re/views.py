import os
import json
from datetime import datetime

from wheezy.web import authorize
from wheezy.caching import logging
from wheezy.security import Principal
from wheezy.html.utils import escape_html
from wheezy.security.crypto import Ticket
from wheezy.web.handlers import BaseHandler
from wheezy.security.crypto.comp import sha1

from models import Registration
from main import Users
from roles import roles
from json_validation import validation_func
from validation import Validation

class HomeHandler(BaseHandler):
    def get(self):
        if not self.principal:
            return self.render_response("non_authorized_home.html")

        user_id = self.principal.id
        users = Users()
        login = users.get_login(user_id)

        if self.principal.roles[0] == "":
            rights = json.loads(users.get_rights(login))
            render_template = "requests.html"
        else:
            rights = [self.principal.roles][0]
            render_template = "authorized_home.html"

        login = escape_html(login)

        return self.render_response(
            render_template,
            login=login,
            rights=rights,
            roles=roles
        )


class RegisterHandler(BaseHandler):
    def get(self):
        if self.principal:
            return self.redirect_for("home")

        registration = Registration()

        return self.render_response(
            "reg_page.html",
            registration=registration,
            script=""
        )

    def post(self):
        registration = Registration()
        validation = Validation()

        try:
            self.try_update_model(registration)
        except:
            pass

        login = registration.login
        password = registration.password
        errors = []
        validation_data = validation.validate_reg_form(
                    login,
                    password,
                    registration.verify
        )

        if not validation_data[0]:
            for key in validation_data[1]:
                errors.append(validation_data[1][key])
            script = f"<p><script>alert({errors})</script></p>"

            return self.render_response(
                "reg_page.html",
                registration=registration,
                script=script
            )
        else:
            users = Users()
            rights = [""]
            login = registration.login
            ticket = Ticket(
                max_age=1200,
                salt='p5sArbHFZvxgeEJFrM9h',
                digestmod=sha1
            )
            enc_password = ticket.encode(password)

            # hashed_password = bcrypt.hashpw(
            #     registration.password.encode(), bcrypt.gensalt()
            # )

            users.sign_up(
                login,
                enc_password,
                json.dumps(rights)
            )

            # user_id = users.get_user_data(login)["id"]

            # self.principal = Principal(
            #     id=str(user_id),
            #     roles=rights
            # )

            return self.redirect_for("home")


class LoginHandler(BaseHandler):
    def get(self):
        if self.principal:
            return self.redirect_for("home")

        return self.render_response("login_page.html")


# class SignUserHandler(BaseHandler):
#     def post(self):
#         registration = Registration()

#         if not self.try_update_model(registration)\
#             or not self.validate(registration, registration_validator):
#             return self.json_response(
#                 {
#                 "success": False,
#                 "errors": self.errors
#                 }
#             )
#         else:
#             users = Users()
#             rights = [""]
#             login = registration.login

#             hashed_password = bcrypt.hashpw(
#                 registration.password.encode(), bcrypt.gensalt()
#             )

#             users.sign_up(
#                 login,
#                 hashed_password,
#                 json.dumps(rights)
#             )

#             user_id = users.get_user_data(login)["id"]

#             self.principal = Principal(
#                 id=str(user_id),
#                 roles=rights
#             )

#         return self.redirect_for("home")



class LoginUserHandler(BaseHandler):
    def post(self):
        form = self.request.form
        users = Users()
        login = form["login"][0]
        password = form["password"][0]

        error = users.login_validation(login, password)
        user_id = users.get_user_data(login)["id"]

        if not error:
            rights = json.loads(users.get_rights(login))
            self.principal = Principal(
                id=str(user_id),
                roles=rights
            )

        return self.json_response({"error": error})



class SnakeHandler(BaseHandler):
    @authorize(roles=("gamer","super"))
    def get(self):
        user_id = self.principal.id
        users = Users()
        stats = users.get_high_scores()
        login = users.get_login(user_id)
        score = users.score_amount(login)
        login = escape_html(login)

        return self.render_response(
            "snake.html",
            login=login,
            score=score,
            stats=stats
        )


class ScoreHandler(BaseHandler):
    def post(self):
        highscore = int(self.request.form["highscore"][0])
        user_id = self.principal.id
        score = int(self.request.form["score"][0])
        time = datetime.now().strftime("%d/%m/%Y %H:%M")
        users = Users()
        users.score_insert(str(user_id), score, time)
        users.high_score_update(highscore, user_id)


class LogoutHandler(BaseHandler):
    def get(self):
        del self.principal

        return self.redirect_for('home')


class MyScoresHandler(BaseHandler):
    @authorize(roles=("gamer","super"))
    def get(self):
        users = Users()
        user_id = self.principal.id
        stats = users.get_stats(str(user_id))

        return self.render_response("scores.html", stats=stats)


class GamesDashboardHandler(BaseHandler):
    @authorize(roles=("gamer","super"))
    def get(self):
        user_id = self.principal.id
        users = Users()
        login = users.get_login(user_id)
        login = escape_html(login)

        return self.render_response("game_dashboard.html", login=login)


class JsonValidationHandler(BaseHandler):
    @authorize(roles=("admin", "super"))
    def get(self):
        return self.render_response("json_val.html")


class ErrorListHandler(BaseHandler):
    @authorize(roles=("admin","super"))
    def get(self):
        return self.render_response("error_list.html")


class GetErrorHandler(BaseHandler):
    def post(self):
        users = Users()
        user_id = self.principal.id
        user_data = users.get_errors(user_id)

        return self.json_response({"errors": user_data})


class UpdateErrorHandler(BaseHandler):
    def post(self):
        if self.request.form:
            data = json.loads(self.request.form["file"][0])
            with open("temp/temp.json", "w") as f:
                json.dump(data, f, indent=6)
        users = Users()
        user_id = self.principal.id
        fixed = 0
        error_list = validation_func("temp/temp.json")
        user_data = users.get_errors(user_id)

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

        return self.json_response({"errors": user_data})


class ChangeRightsHandler(BaseHandler):
    @authorize(roles=("super",))
    def get(self):
        users = Users()
        rights = users.get_all_rights()
        requests = users.get_all_requests()
        logins = []
        requests_list = []
        right_list = []

        for request in requests:
            if request["request"]:
                requests_list.append(json.loads(request["request"]))
            else:
                requests_list.append(None)

        for user in rights:
            right_list.append(json.loads(user["rights"]))
            logins.append(escape_html(user["login"]))

        return self.render_response(
            "change_rights.html",
            right=right_list, 
            login=logins,
            requests=requests_list,
            roles=roles
        )


class PostNewHandler(BaseHandler):
    def post(self):
        form = self.request.form
        roles = []
        users = Users()
        for htmllogin in form:
            login = users.html_decrypt(htmllogin)
            roles = form[htmllogin]
            users.change_roles(login, json.dumps(roles))

        return self.json_response({"status": "ok"})


class RequestDelete(BaseHandler):
    def post(self):
        form = self.request.form
        users = Users()
        for htmllogin in form:
            login = users.html_decrypt(htmllogin)
            print(users.get_request(login))
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


class RequestHandler(BaseHandler):
    @authorize()
    def get(self):
        user_id = self.principal.id
        users = Users()
        login = users.get_login(user_id)
        rights = json.loads(users.get_rights(login))
        login = escape_html(login)
        return self.render_response(
            "requests.html",
            login=login, 
            rights=rights, 
            roles=roles
        )


class SubmitRequestHandler(BaseHandler):
    def post(self):
        form = self.request.form
        req = form.get("request")
        data_req = json.dumps(req)
        users = Users()
        user_id = self.principal.id
        login = users.get_login(user_id)
        users.post_requests(login, data_req)

        return self.json_response(
            {
                "status": "ok",
                "message": f"Your request is sent to super"
            }
        )
