from datetime import timedelta

from wheezy.routing import url
from wheezy.http import response_cache
from wheezy.http.transforms import gzip_transform
from wheezy.http.transforms import response_transforms
from wheezy.web.handlers import file_handler
from wheezy.http import CacheProfile
from wheezy.http.cache import etag_md5crc32

from views import (
    HomeHandler,
    RegisterHandler,
    LoginUserHandler,
    SignUserHandler,
    LoginHandler,
    SnakeHandler, 
    ScoreHandler,
    LogoutHandler,
    MyScoresHandler,
    GamesDashboardHandler, 
    JsonValidationHandler,
    ErrorListHandler,
    UpdateErrorHandler,
    ChangeRightsHandler,
    PostNewHandler,  
    GetErrorHandler,
    RequestDelete,
    RequestHandler,
    SubmitRequestHandler
)


static_cache_profile = CacheProfile(
    "public",
    duration=timedelta(minutes=15),
    vary_environ=["HTTP_ACCEPT_ENCODING"],
    namespace="static",
    http_vary=["Accept-Encoding"],
    etag_func=etag_md5crc32,
    enabled=True
)

static_files = response_cache(static_cache_profile)(
    response_transforms(gzip_transform(compress_level=6))(
        file_handler(
            root='templates/static/')))

all_urls = [
    url("home", HomeHandler, name="home"),
    #Signing
    url("register", RegisterHandler, name="Register"),
    url("login", LoginHandler, name="login"),
    url("login/user", LoginUserHandler, name="login_user"),
    url("signup/user", SignUserHandler, name="sign_user"),
    url("logout", LogoutHandler, name="logout"),
    #Games
    url("snake", SnakeHandler),
    url("games", GamesDashboardHandler),
    url("snake/user", ScoreHandler, name="snake_user"),
    url("scores", MyScoresHandler, name="scores"),
    #Validator
    url("validator", JsonValidationHandler),
    url("errors", ErrorListHandler),
    url("get/error", GetErrorHandler),
    url("update/error", UpdateErrorHandler),
    #SuperAdmins
    url("changerights", ChangeRightsHandler),
    # url("get/roles", SendRolesHandler),
    url("post/new/roles", PostNewHandler),
    #Requests
    url("requestrights", RequestHandler),
    url("submitrequests", SubmitRequestHandler),
    url("req/del", RequestDelete),
    #Static folder
    url('static/{path:any}', static_files, name='static')
]
