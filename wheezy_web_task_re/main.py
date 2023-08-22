import os
import json
from db import DataBase
from json_validation import validation_func


class Users(DataBase):
        
    def check_username(self, login: str) -> dict:
        """
        Check Username
        -----------
        Parameters
        login : str
        -----------
        return dict
        """
        return self.select(
            """
                SELECT login FROM users
                WHERE login=:login 
            """,
            values={"login": login},
        )

        
    def sign_up(self, login: str, password: str):
        """
        Adding new user to db
        -----------
        Parameters
        login : str
        password : str
        """
        self.change(
            """
                INSERT INTO users (login, password, score, rights, request)
                VALUES (:login, :password, 0, '[""]', '[]')
            """,
            {'login':login, "password": password}
        )


    def get_user_data(self, login: str) -> dict:
        """
        Logging
        -----------
        Parameters
        login : str
        -----------
        return dict
        """
        return self.select(
            """
                SELECT id, login, password FROM users
                WHERE login = :login
            """, 
            values = {"login": login},
        )
        
    
    def get_password(self, login: str) -> dict:
        """
        Getting encrypted password
        -----------
        Parameters
        login : str
        -----------
        return dict
        """
        return self.select(
            """
                SELECT login, password FROM users
                WHERE login = :login
            """,
            values = {"login": login},
        )

    
    def score_amount(self, login: str) -> int:
        """
        Get score of user, rights
        -----------
        Parameters
        login : str
        -----------
        return int
        """
        return self.select(
            """
                SELECT score FROM users
                WHERE login = :login
            """, 
            values={"login": login},
            key="score"
        )



    def get_login(self, id: str) -> str:
        """
        Get id, login from db
        -----------
        Parameters
        id : str
        -----------
        return str
        """
        return self.select(
            """
                SELECT login FROM users
                WHERE id = :id
            """, 
            values={"id": id},
            key="login"
        )


    
    def get_no_super_logins(self) -> list:
        """
        Get all logins from db except 'super'
        -----------
        Parameters
        -----------
        return list
        """
        return self.select(
            """
                SELECT login FROM users
                WHERE rights != '["super"]'
            """,
            fetch_method="all"
        )


    def high_score_update(self, score: int, id: str):
        """
        Update High Score of user
        -----------
        Parameters
        score : int
        id : str
        """
        self.change(
            """
                UPDATE users
                SET score = :score
                WHERE id = :id
            """,
            {'score':score, 'id':id}
        )

    def score_insert(self, id: str, score: int, time: str):
        """
        Insert score data of user
        -----------
        Parameters
        id : str
        score : int
        time : str
        """
        self.change(
            """
                INSERT INTO stats (userID, score, date)
                VALUES (:id, :score, :time)
            """,
            {'id': id, 'score': score, 'time': time}
        )

    def get_stats(self, id: str) -> object:
            """
            Get Stats
            -----------
            Parameters
            id : str
            -----------
            return object
            """
            return self.select(
                """
                    SELECT score, date FROM stats
                    WHERE userID = :id
                """,
                values = {'id': id},
                fetch_method="all"
            )
    
    def get_high_scores(self) -> list:
            """
            Order and return HighScores
            -----------
            Parameters
            -----------
            return list
            """
            return self.select(
                 """
                    SELECT login, score FROM users
                    ORDER BY score DESC;
                 """,
                fetch_method="all"
            )
        
    def get_rights(self, login: str) -> str:
        
        """
        Get rights of user
        -----------
        Parameters
        login : str
        -----------
        return str
        """
        return self.select(
            """
                SELECT rights FROM users
                WHERE login = :login
            """, 
            values = {"login": login},
            key = "rights"
        )
    
    def get_all_rights(self) -> list:
        """
        Get rights of user
        -----------
        Parameters
        login : str
        -----------
        return list
        """
        return self.select(
            "SELECT login, rights FROM users",
            fetch_method = "all"
        )

    
    def change_roles(self, login: str, role: str = '[""]'):
        """
        Changing roles of the user
        -----------
        Parameters
        login : str
        role : str
        """
        self.change(
            """
            UPDATE users
            SET rights = :role
            WHERE login = :login

            """,
            {"login":login, "role": role}
        )

    def insert_errors(self, user_id: int, error: str, fixed: int):
        """
        Insert Errors for Validator
        -----------
        Parameters
        user_id : int
        error : str
        fixed : int
        """
        self.change(
            """
                INSERT INTO error_list (user_id, errors, fixed)
                SELECT :user_id, :error, :fixed
                WHERE NOT EXISTS (
                    SELECT 1 FROM error_list \
                    WHERE errors = :error AND user_id = :user_id)
            """,
            {"user_id": user_id, "error": error, "fixed": fixed}
        )
    
    def get_errors(self, user_id: int) -> list:
        """
        Getting Errors by user_id
        -----------
        Parameters
        user_id : int
        -----------
        return list
        """
        return self.select(
            """
                SELECT errors, fixed FROM error_list
                WHERE user_id = :user_id
            """,
            values = {"user_id": user_id},
            fetch_method = "all"
        )
    
    def update_errors(self, user_id: int, error: str, fixed: int):
        """
        Update Errors for Validator
        -----------
        Parameters
        user_id : int
        error : str
        fixed : int
        """
        self.change(
            """
                UPDATE error_list
                SET fixed = :fixed
                WHERE user_id = :user_id AND errors = :error
            """,
            {"user_id":user_id, "error": error, "fixed": fixed}
        )
    
    def post_requests(self, login: str, request: str):
        """
        Update requests column
        -----------
        Parameters
        login : str
        request: str
        """
        self.change(
            """
                UPDATE users
                SET request = :request
                WHERE login = :login
            """,
            {"login":login,"request": request}
        )

    def get_all_requests(self) -> list:
        """
        Get requests of user
        -----------
        Parameters
        -----------
        return list
        """

        return self.select(
            "SELECT request FROM users",
            fetch_method = "all"
        )


    def get_request(self, login: str) -> str:
        """
        Get requests by login
        -----------
        Parameters
        login : str
        -----------
        return str
        """

        return self.select(
            """
                SELECT request FROM users
                WHERE login=:login
            """,
            values = {"login": login},
            key = "request"
        )
    
    def delete_user(self, user_id: int):
        """
        Delete user from table
        -----------
        Parameters
        user_id : int
        """
        self.change(
            """
                DELETE FROM users
                WHERE id=:user_id
            """,
            values= {"user_id": user_id}
        )

        self.change(
            """
                DELETE FROM error_list
                WHERE user_id=:user_id
            """,
            values= {"user_id": user_id}
        )

        self.change(
            """
                DELETE FROM stats
                WHERE userID=:user_id
            """,
            values= {"user_id": user_id}
        )


class Main:
    def updateErrors(self, user_id):
        users = Users()
        fixed = 0
        error_list = validation_func("temp/temp.json")
        user_data = users.get_errors(user_id)
        for user in user_data:
            if user["errors"] not in error_list:
                fixed = 1
                users.update_errors(user_id, user["errors"], fixed)
            elif user["fixed"]:
                fixed = 0
                users.update_errors(user_id, user["errors"], fixed)
        for error in error_list:
            users.insert_errors(user_id, error, fixed)
        if os.path.exists("temp/temp.json"):
            os.remove("temp/temp.json")

    def changeRights(self, model):
        users = Users()
        rights_dict = {}
        old_req = []
        for item in model.rights:
            item = json.loads(item)
            key = list(item.keys())[0]
            value = list(item.values())[0]
            if key in rights_dict:
                rights_dict[key].append(value)
            else:
                rights_dict[key] = [value]

        usr_data = users.get_no_super_logins()
        login_list = []
        for data in usr_data:
            login_list.append(data["login"])

        for usr in login_list:
            if not usr in rights_dict:
                users.change_roles(usr)

        for login in rights_dict:
            rights = json.dumps(rights_dict[login])
            users.change_roles(login, rights)

            req = json.loads(users.get_request(login))
            old_req = json.loads(users.get_request(login))

            if len(req) > 0:
                for request in req:
                    if request in rights:
                        old_req.remove(request)
                
                users.post_requests(
                    login=login,
                    request=json.dumps(old_req)
                )
