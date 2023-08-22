from wheezy.html.utils import escape_html

class Registration():
    def __init__(self):
        self.login = ""
        self.password = ""
        self.verify = ""


class Login():
    def __init__(self):
        self.login = escape_html("")
        self.password = escape_html("")


class Rights():
    def __init__(self):
        self.request = []


class ChangeRights():
    def __init__(self):
        self.rights = []