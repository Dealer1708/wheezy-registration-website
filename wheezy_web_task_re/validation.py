from main import Users
import bcrypt

class Validation():
    def validate_reg_form(self, login: str, password: str, verify: str):
        users = Users()
        error_message = {}
        success = True
        if login:
            if len(login) > 10:
                success = False
                error_message["login"] =\
                    "Login must be no more than 10 characters"
            elif users.check_username(login):
                success = False
                error_message["login"] = "Login exists"
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

        return True, error_message
    

    def validate_login_form(self, login: str, password: str):
        users = Users()

        if (users.check_username(login)) and\
            (password_from_data := users.get_password(login)) and\
            bcrypt.checkpw(password.encode(), password_from_data["password"]):
            return True, None

        return False, "Incorrect Login or Password Try again"
    
            



# registration_validator = Validator(
#     {
#         "login": [
#             required(message_template="Login required"),
#             length(
#                 max=10,
#                 message_template="Login must be no more than 10 characters"
#             )
#         ],
#         "password": [
#             required(message_template="Password required"),
#             length(
#                 min=8,
#                 message_template="Password must have at least 8 characters"
#             )
#         ],
#         "verify": [
#             compare(
#                 equal="password",
#                 message_template="Passwords need to match"
#             )
#         ]
#     }
# )

