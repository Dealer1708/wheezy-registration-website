from wheezy.security import Principal
from main import Users

import bcrypt
import json


class Authorization:
    def validate_reg_form(self, login: str, password: str, verify: str) -> str:
        """
        Registration form validation and authorization if success
        -----------
        Parameters
        login : str
        password : str
        verify : str
        -----------
        return str
        """
        users = Users()
        try:
            if login:
                if len(login) > 10:
                    raise Exception("Login must be no more than 10 characters")
                elif users.check_username(login):
                    raise Exception("Login exists")
            else:
                raise Exception("Login required")
            
            if password:
                if len(password) < 8:
                    pass
                    # raise Exception("Password must have at least 8 characters")
            else:
                raise Exception("Password required")
            
            if verify != password:
                raise Exception("Passwords need to match")
            
            #auth
            enc_password = bcrypt.hashpw(
                password.encode(), bcrypt.gensalt()
            )
            
            users.sign_up(login, enc_password)
            id = str(Users().get_user_data(login)["id"])

            return self.authorization(id=id, rights=[""])

        except Exception as error:
            return error

    def validate_login_form(self, login: str, password: str) -> tuple:
        """
        Login form validation
        -----------
        Parameters
        login : str
        password : str
        -----------
        return tuple
        """
        users = Users()

        if (users.check_username(login)) and\
            (password_from_data := users.get_password(login)) and\
            bcrypt.checkpw(password.encode(), password_from_data["password"]):

                rights = json.loads(users.get_rights(login))
                id = str(Users().get_user_data(login)["id"])
                return self.authorization(id=id, rights=rights)

        return Exception("Incorrect login or password")

    def authorization(self, id: str, rights: str):
        return Principal(id=id, roles=rights)
