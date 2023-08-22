from wheezy.routing import url
from wheezy.web.handlers import file_handler

from views import (
    HomeHandler,
    RegisterHandler,
    LoginHandler,
    SnakeHandler, 
    LogoutHandler,
    MyScoresHandler,
    GamesDashboardHandler, 
    JsonValidationHandler,
    UpdateErrorHandler,
    ChangeRightsHandler,
    GetErrorHandler,
    RequestHandler
)
static_files = file_handler(root='templates/static/')

all_urls = [
    url("home", HomeHandler, name="home"),
    #Signing
    url("register", RegisterHandler, name="register"),
    url("login", LoginHandler, name="login"),
    url("logout", LogoutHandler, name="logout"),
    #Games
    url("snake", SnakeHandler),
    url("games", GamesDashboardHandler),
    url("scores", MyScoresHandler, name="scores"),
    #Validator
    url("validator", JsonValidationHandler),
    url("update/get/errors", GetErrorHandler),
    url("update/error", UpdateErrorHandler),
    #SuperAdmins
    url("changerights", ChangeRightsHandler),
    #Requests
    url("requestrights", RequestHandler, name="requests"),
    #Static folder
    url('static/{path:any}', static_files, name='static')
]