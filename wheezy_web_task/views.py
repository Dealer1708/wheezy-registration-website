import bcrypt
from datetime import datetime
from wheezy.web import authorize
from wheezy.security import Principal
from wheezy.web.handlers import BaseHandler

from main import Users


class NonLogHomeHandler(BaseHandler):
    def get(self):
        if self.principal == None:
            return self.render_response("non_log_home.html")
        else:
            user_id = self.principal.id
            users = Users()
            login = users.loginName(user_id)[1]
            login = login\
                .replace("<", "&lt;")\
                .replace(">", "&gt;")\
                .replace('"', "&quot;")\
                .replace("'", "&#39;")

            return self.render_response("log_home.html", login=login)


class RegisterHandler(BaseHandler):
    def get(self):
        if self.principal != None:
            return self.redirect_for("home")

        return self.render_response("reg_page.html")


class LoginHandler(BaseHandler):
    def get(self):
        if self.principal != None:
            return self.redirect_for("home")

        return self.render_response("login_page.html")


class SignUserHandler(BaseHandler):
    def post(self):
        form = self.request.form
        users = Users()
        new_user_name = form['login'][0]
        new_user_password = form['password'][0]
        if new_user_password != form['verify'][0]:
            return self.json_response(
                {
                    "status": "Fail",
                    "message": "Passwords dont match",
                    "field": "verify"
                })
        if users.check_username(new_user_name):
            return self.json_response(
                {
                    "status": "Fail",
                    "message": "Login exists",
                    "field": "login"
                })
        hashed_password = bcrypt.hashpw(new_user_password.encode(), bcrypt.gensalt())
        users.sign_up(new_user_name, hashed_password)
        user = users.login(new_user_name, hashed_password)
        self.principal = Principal(id=str(user[0]))

        return self.json_response({"status": "ok"})


class LoginUserHandler(BaseHandler):
    def post(self):
        form = self.request.form
        users = Users()
        login = form["login"][0]
        password = form["password"][0]
        password_from_data = users.getPassword(login)
        if password_from_data != None:
            user = users.login(login, password_from_data[1])
            if bcrypt.checkpw(password.encode(), password_from_data[1]) == False:
                return self.json_response({"status": "Fail"})
            else:
                self.principal = Principal(id=str(user[0]))
                return self.json_response({"status": "ok"})
        
    def get(self):
        return self.render_response("log_home.html")


class SnakeHandler(BaseHandler):
    @authorize()
    def get(self):
        user_id = self.principal.id
        users = Users()
        login = users.loginName(user_id)[1]
        score = users.scoreAmount(login)[1]
        login = login\
            .replace("<", "&lt;")\
            .replace(">", "&gt;")\
            .replace('"', "&quot;")\
            .replace("'", "&#39;")

        return self.render_response("snake.html", login=login, score=score)


class ScoreHandler(BaseHandler):
    def post(self):
        highscore = int(self.request.form["highscore"][0])
        user_id = self.principal.id
        score = int(self.request.form["score"][0])
        date = datetime.now().strftime("%d/%m/%Y")
        time = datetime.now().strftime("%H:%M")
        users = Users()
        users.scoreInsert(str(user_id),score,date,time)
        users.highScoreUpdate(highscore, user_id)


class ScoreSendHandler(BaseHandler):
        def post(self):
            users = Users()
            user_id = self.principal.id
            stats = users.getStats(str(user_id))
            return self.json_response({"body": stats})
        

class LeaderBoardSendHandler(BaseHandler):
    def post(self):
        users = Users()
        stats = users.sortHighScores()
        return self.json_response({"body": stats})


class LogoutHandler(BaseHandler):
    def get(self):
        del self.principal

        return self.redirect_for('home')
    

class LeaderBoardHandler(BaseHandler):
    def post(self):
        Users().test()

    def get(self):
        return self.render_response("leaderboard.html")


class MyScoresHandler(BaseHandler):
    @authorize()
    def get(self):
        return self.render_response("scores.html")