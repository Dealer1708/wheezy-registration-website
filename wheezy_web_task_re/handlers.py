from wheezy.web.handlers import BaseHandler
from wheezy.security import Principal
from wheezy.http import HTTPCookie

from config import options, ticket
from main import Users

class MainHandler(BaseHandler):
    def getprincipal(self):
        if hasattr(self, "_BaseHandler__principal"):
            return self.__principal
        principal = None
        auth_cookie = self.request.cookies.get(
            self.options["AUTH_COOKIE"], None
        )
        if auth_cookie is not None:
            auth_ticket = self.ticket
            ticket1, time_left = auth_ticket.decode(auth_cookie)
            if ticket1:
                principal = Principal.load(ticket1)
                if time_left < auth_ticket.max_age / 2:
                    # renew
                    enc_login = ticket.encode(
                        Users().get_login(ticket1.split("\x1f")[0])
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
                    self.setprincipal(principal)
                    return principal
            else:
                self.cookies.append(
                    HTTPCookie.delete(
                        name="user_login",
                        options=options
                    )
                )
                self.delprincipal()
        self.__principal = principal
        return principal
    
    def setprincipal(self, principal):
        options = self.options
        self.cookies.append(
            HTTPCookie(
                options["AUTH_COOKIE"],
                value=self.ticket.encode(principal.dump()),
                path=self.request.root_path + options["AUTH_COOKIE_PATH"],
                domain=options["AUTH_COOKIE_DOMAIN"],
                secure=options["AUTH_COOKIE_SECURE"],
                httponly=True,
                options=options,
            )
        )
        self.__principal = principal

    def delprincipal(self):
        options = self.options
        self.cookies.append(
            HTTPCookie.delete(
                options["AUTH_COOKIE"],
                path=self.request.root_path + options["AUTH_COOKIE_PATH"],
                domain=options["AUTH_COOKIE_DOMAIN"],
                options=options,
            )
        )
        self.__principal = None
    
    principal = property(getprincipal, setprincipal, delprincipal)