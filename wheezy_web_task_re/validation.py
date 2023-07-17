from wheezy.validation import Validator
from wheezy.validation.rules import length, required, compare
from wheezy.html.utils import escape_html


class Validation():
    def validate_reg_form(self, login, password, verify):
        error_message = {}
        success = True
        if login:
            if len(login) > 10:
                success = False
                error_message["login"] =\
                    "Login must have not more than 10 characters"
                # if login not exists in db:
        else:
            success = False
            error_message["login"] = "Login required"
        
        if password:
            if len(password) < 8:
                success = False
                error_message["password"] =\
                    "Password must have at least 8 characters"
        else:
            success = False
            error_message["password"] = "Password required"
        
        if verify != password:
            success = False
            error_message["verify"] = "Passwords need to match"

        return [success, error_message]
            



# registration_validator = Validator(
#     {
#         "login": [required, length(max=10)],
#         "password": [required, length(min=8)],
#         "verify": [compare(equal="password")]
#     }
# )

