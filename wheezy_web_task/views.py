import os
import json
import bcrypt
from datetime import datetime

from wheezy.web import authorize
from wheezy.security import Principal
from wheezy.web.handlers import BaseHandler

from main import Users
from roles import roles
from json_validation import validation_func


class HomeHandler(BaseHandler):
    def get(self):
        if not self.principal:
            return self.render_response("non_authorized_home.html")

        user_id = self.principal.id
        users = Users()
        login = users.get_login(user_id)[1]

        if self.principal.roles[0] == "":
            rights = json.loads(users.get_rights(login)[1])["rights"]
            render_template = "requests.html"
        else:
            rights = [self.principal.roles][0]
            render_template = "authorized_home.html"

        login = users.login_name_validation(login)

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

        return self.render_response("reg_page.html")


class LoginHandler(BaseHandler):
    def get(self):
        if self.principal:
            return self.redirect_for("home")

        return self.render_response("login_page.html")


class SignUserHandler(BaseHandler):
    def post(self):
        form = self.request.form
        users = Users()
        user_name = form['login'][0]
        user_password = form['password'][0]
        verify_password = form['verify'][0]
        rights = {"rights": [""]}

        status = users.sign_up_validation(
            user_name,
            user_password,
            verify_password
        )

        hashed_password = bcrypt.hashpw(
            user_password.encode(), bcrypt.gensalt()
        )

        if status["status"]:
            users.sign_up(user_name, hashed_password, json.dumps(rights))
            user = users.get_user_data(user_name)
            self.principal = Principal(
                id=str(user[0]),
                roles=rights["rights"]
            )

        return self.json_response(
            {
            "status": status["status"],
            "message": status["message"]
            }
        )


class LoginUserHandler(BaseHandler):
    def post(self):
        form = self.request.form
        users = Users()
        login = form["login"][0]
        password = form["password"][0]

        error = users.login_validation(login, password)
        user = users.get_user_data(login)

        if not error:
            rights = json.loads(users.get_rights(login)[1])["rights"]
            self.principal = Principal(
                id=str(user[0]),
                roles=rights
            )

        return self.json_response({"error": error})



class SnakeHandler(BaseHandler):
    @authorize(roles=("gamer","super"))
    def get(self):
        user_id = self.principal.id
        users = Users()
        stats = users.get_high_scores()
        login = users.get_login(user_id)[1]
        score = users.score_amount(login)[1]
        login = users.login_name_validation(login)

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
        login = users.get_login(user_id)[1]
        login = users.login_name_validation(login)

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
            if user[0] not in error_list:
                fixed = 1
                users.update_errors(user_id, user[0], fixed)
            elif user[1]:
                fixed = 0
                users.update_errors(user_id, user[0], fixed)

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
            if request[0]:
                requests_list.append(json.loads(request[0])["requests"])
            else:
                requests_list.append(list(request))

        for user in rights:
            right_list.append(json.loads(user[1])["rights"])
            logins.append(users.login_name_validation(user[0]))

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
        roles = {"rights" : []}
        users = Users()
        for htmllogin in form:
            login = users.html_decrypt(htmllogin)
            roles["rights"] = form[htmllogin]
            users.change_roles(login, json.dumps(roles))

        return self.json_response({"status": "ok"})


class RequestDelete(BaseHandler):
    def post(self):
        form = self.request.form
        users = Users()
        for htmllogin in form:
            login = users.html_decrypt(htmllogin)
            old_req = json.loads(users.get_request(login)[0])["requests"]
            for i in form[htmllogin]:
                if i in old_req:
                    old_req.remove(i)
                    if len(old_req) == 0:
                        users.set_request_null(login=login)
                    else:
                        users.post_requests(
                            login=login,
                            request=json.dumps({"requests": old_req})
                        )

        return self.json_response({"status": "ok"})


class RequestHandler(BaseHandler):
    @authorize()
    def get(self):
        user_id = self.principal.id
        users = Users()
        login = users.get_login(user_id)[1]
        rights = json.loads(users.get_rights(login)[1])["rights"]
        login = users.login_name_validation(login)
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
        data_req = json.dumps({"requests": req})
        users = Users()
        user_id = self.principal.id
        login = users.get_login(user_id)[1]
        users.post_requests(login, data_req)

        return self.json_response(
            {
                "status": "ok",
                "message": f"Your request is sent to super"
            }
        )
