from views import (NonLogHomeHandler, RegisterHandler, LoginUserHandler, 
                   SignUserHandler, LoginHandler, SnakeHandler, 
                   ScoreHandler, LogoutHandler, LeaderBoardHandler,
                   MyScoresHandler, ScoreSendHandler, LeaderBoardSendHandler)
from wheezy.routing import url
from wheezy.http import response_cache
from wheezy.http.transforms import gzip_transform
from wheezy.http.transforms import response_transforms
from wheezy.web.handlers import file_handler
from datetime import timedelta
from wheezy.http import CacheProfile
from wheezy.http.cache import etag_md5crc32

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
    url("home", NonLogHomeHandler, name="home"),
    url("register", RegisterHandler, name="Register"),
    url("login", LoginHandler, name="login"),
    url("login/user", LoginUserHandler, name="login_user"),
    url("signup/user", SignUserHandler, name="sign_user"),
    url("snake", SnakeHandler, name="snake"),
    url("snake/user", ScoreHandler, name="snake_user"),
    url("logout", LogoutHandler, name="logout"),
    url("leaderboard", LeaderBoardHandler, name="leaderboard"),
    url("scores", MyScoresHandler, name="scores"),
    url("score/user", ScoreSendHandler),
    url("leaderboard/user", LeaderBoardSendHandler),
    #static
    url('static/{path:any}', static_files, name='static')
]
