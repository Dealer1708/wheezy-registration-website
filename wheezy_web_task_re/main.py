import json
import bcrypt
import sqlite3
from config import ticket
from wheezy.security import Principal

def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d


class Users():
    def __init__(self):
        db = sqlite3.connect('data.db')
        db.row_factory = dict_factory
        self.cursor = db.cursor()
    
    def change(self,sql_query,login={}):
        db = sqlite3.connect('data.db')
        db.row_factory = dict_factory
        self.cursor = db.cursor()
        self.cursor.execute(f"""{sql_query}""",login)
        db.commit()
        db.close()

    def select(self,sql_query,login={}, fetch_method="fetchone"):
        db = sqlite3.connect('data.db')
        db.row_factory = dict_factory
        self.cursor = db.cursor()
        self.cursor.execute(f"""{sql_query}""",login)


    def check_username(self, login: str) -> object:
        """
        Check Username
        -----------
        Parameters
        login : str
        -----------
        return object
        """
        self.select(
            """
                SELECT login FROM users
                WHERE login=:login 
            """,
            {'login': login}
        )
        result = self.cursor.fetchone()
        self.close_cursor()
        return result
        
    def sign_up(self, login: str, password: str, rights: str) -> int:
        """
        Adding new user to db
        -----------
        Parameters
        login : str
        password : str
        -----------
        return int
        """
        self.change(
            """
                INSERT INTO users (login, password, score, rights, request)
                VALUES (:login, :password, 0, :rights, '[]')
            """,
            {'login':login, "password": password, "rights": rights}
        )


    def get_user_data(self, login: str) -> object:
        """
        Logging
        -----------
        Parameters
        login : str
        -----------
        return object
        """
        self.select(
            """
                SELECT id, login, password FROM users
                WHERE login = :login
            """, 
            {"login": login}
        )

        result = self.cursor.fetchone()
        self.close_cursor()
        return result
    
    def get_password(self, login: str) -> bytes:
        """
        Getting encrypted password
        -----------
        Parameters
        login : str
        -----------
        return bytes
        """
        self.select(
            """
                SELECT login, password FROM users
                WHERE login = :login
            """,
            {"login": login}
        )

        result = self.cursor.fetchone()
        self.close_cursor()
        return result
    
    def score_amount(self, login: str) -> object:
        """
        Get score of user, rights
        -----------
        Parameters
        login : str
        -----------
        return object
        """
        self.select(
            """
                SELECT score FROM users
                WHERE login = :login
            """, 
            {"login": login}
        )

        result = self.cursor.fetchone()["score"]
        self.close_cursor()
        return result

    def get_login(self, id: str) -> object:
        """
        Get id, login from db
        -----------
        Parameters
        id : str
        -----------
        return object
        """
        self.select(
            """
                SELECT login FROM users
                WHERE id = :id
            """, 
            {"id": id}
        )

        result = self.cursor.fetchone()["login"]
        self.close_cursor()
        return result
    
    def get_no_super_logins(self) -> object:
        """
        Get logins from db
        -----------
        Parameters
        -----------
        return object
        """
        self.select(
            """
                SELECT login FROM users
                WHERE rights != '["super"]'
            """
        )

        result = self.cursor.fetchall()
        self.close_cursor()
        return result

    def high_score_update(self, score: int, id: str) -> int:
        """
        Update High Score of user
        -----------
        Parameters
        score : int
        id : str
        -----------
        return int
        """
        self.change(
            """
                UPDATE users
                SET score = :score
                WHERE id = :id
            """,
            {'score':score, 'id':id}
        )

    def score_insert(self, id: str, score: int, time: str) -> int:
        """
        Insert score data of user
        -----------
        Parameters
        id : str
        score : int
        time : str
        -----------
        return int
        """
        self.change(
            """
                INSERT INTO stats (userID, score, date)
                VALUES (:id, :score, :time)
            """,
            {'id': id, 'score': score, 'time': time}
        )

    def get_stats(self, id: str) -> int:
            """
            Get Stats
            -----------
            Parameters
            id : str
            -----------
            return int
            """
            self.select(
                """
                    SELECT score, date FROM stats
                    WHERE userID = :id
                """,
                {'id': id}
            )
            
            return self.cursor
    
    def get_high_scores(self):
            """
            Order and return HighScores
            -----------
            Parameters
            -----------
            return int
            """
            self.select(
                 """
                    SELECT login, score FROM users
                    ORDER BY score DESC;
                 """
            )

            result = self.cursor.fetchall()
            self.close_cursor()
            return result
        
    def get_rights(self, login: str) -> object:
        
        """
        Get rights of user
        -----------
        Parameters
        login : str
        -----------
        return object
        """
        self.select(
            """
                SELECT rights FROM users
                WHERE login = :login
            """, 
            {"login": login}
        )

        result = self.cursor.fetchone()["rights"]
        self.close_cursor()
        return result
    
    def get_all_rights(self) -> object:
        """
        Get rights of user
        -----------
        Parameters
        login : str
        -----------
        return object
        """
        self.select("SELECT login, rights FROM users")

        result = self.cursor.fetchall()
        return result
    
    def change_roles(self, login: str, role: str) -> object:
        """
        Changing roles of the user
        -----------
        Parameters
        login : str
        role : str
        -----------
        return object
        """
        self.change(
            """
            UPDATE users
            SET rights = :role
            WHERE login = :login

            """,
            {"login":login, "role": role}
        )

    def insert_errors(self, user_id: int, error: str, fixed: int) -> object:
        """
        Insert Errors for Validator
        -----------
        Parameters
        user_id : int
        error : str
        fixed : int
        -----------
        return object
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
    
    def get_errors(self, user_id: int) -> object:
        """
        Getting Errors by user_id
        -----------
        Parameters
        user_id : int
        -----------
        return object
        """
        self.select(
            """
                SELECT errors, fixed FROM error_list
                WHERE user_id = :user_id
            """,
            {"user_id": user_id}
        )

        result = self.cursor.fetchall()
        self.close_cursor()
        return result
    
    def update_errors(self, user_id: int, error: str, fixed: int) -> object:
        """
        Update Errors for Validator
        -----------
        Parameters
        user_id : int
        error : str
        fixed : int
        -----------
        return object
        """
        self.change(
            """
                UPDATE error_list
                SET fixed = :fixed
                WHERE user_id = :user_id AND errors = :error
            """,
            {"user_id":user_id, "error": error, "fixed": fixed}
        )
    
    def post_requests(self, login: str, request: str) -> object:
        """
        Update requests column
        -----------
        Parameters
        login : str
        request: str
        -----------
        return object
        """
        self.change(
            """
                UPDATE users
                SET request = :request
                WHERE login = :login
            """,
            {"login":login,"request": request}
        )

    def get_all_requests(self) -> object:
        """
        Get requests of user
        -----------
        Parameters
        -----------
        return object
        """

        self.select("SELECT request FROM users")

        result = self.cursor.fetchall()
        self.close_cursor()
        return result

    def get_request(self, login: str) -> object:
        """
        Get requests by login
        -----------
        Parameters
        login : str
        -----------
        return object
        """

        self.select(
            """
                SELECT request FROM users
                WHERE login=:login
            """,
            {"login":login}
        )

        result = self.cursor.fetchone()["request"]
        self.close_cursor()
        return result

    def set_request_null(self, login: str) -> object:
        """
        Set requests to [] by login
        -----------
        Parameters
        login : str
        -----------
        return object
        """

        self.change(
            """
                UPDATE users set request = '[]'
                WHERE login =:login
            """,
            {"login":login}
        )

    # def login_name_validation(self, login: str):
    #     """
    #     JS inject Protection
    #     -----------
    #     Parameters
    #     login : str
    #     -----------
    #     return object
    #     """
    #     login = login\
    #         .replace("<", "&lt;")\
    #         .replace(">", "&gt;")\
    #         .replace('"', "&quot;")\
    #         .replace("'", "&#39;")

    #     return login

    def html_decrypt(self, login: str):
        db = sqlite3.connect('data.db')
        db.row_factory = dict_factory
        self.cursor = db.cursor()
        login = login\
            .replace("&lt;", "<")\
            .replace("&gt;", ">")\
            .replace("&quot;", '"')\
            .replace("&#39;", "'")\
            .replace("%22", '"')

        return login
    
    def sign_up_validation(self, login: str, password: str, verify: str) -> dict:
        db = sqlite3.connect('data.db')
        db.row_factory = dict_factory
        self.cursor = db.cursor()
        status = True
        message = ""

        if login == "" or password == "":
            status = False
            message = "Please, fill all the fields."

        if len(password) < 8:
            status = False
            message = "Password needs to have atleast 8 characters"

        else:
            capital_letter_in_psw = False
            digit_in_psw = False
            for symbol in password:
                if symbol.isdigit():
                    digit_in_psw = True
                if symbol.isupper():
                    capital_letter_in_psw = True

            if not capital_letter_in_psw:
                status = False
                message = "Password needs to have atleast 1 capital letter"
            if not digit_in_psw:
                status = False
                message = "Password needs to have atleast 1 digit"
            
        if password != verify:
            status = False
            message = "Passwords don't match"

        if self.check_username(login):
            status = False
            message = "Login exists"

        return {"status":status, "message":message}
    
    def close_cursor(self):
        db = sqlite3.connect('data.db')
        db.row_factory = dict_factory
        db.close()
