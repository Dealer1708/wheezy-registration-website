import sqlite3

db = sqlite3.connect('data.db')

class Users():
    def __init__(self):
        self.cursor = db.cursor()

    def get_all(self):
        self.cursor.execute('SELECT login FROM users')

        return self.cursor.fetchall()
    
    def check_username(self, login: str) -> object:
        """
            Check Username
            -----------
            Parameters
            login : str
            -----------
            return object
        """
        self.cursor.execute(
            """
                SELECT login FROM users
                WHERE login=:login 
            """,
            {'login':login})

        return self.cursor.fetchone()
    
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
        self.cursor.execute(
            """
                INSERT INTO users (login, password, score, rights)
                VALUES (:login, :password, 0, :rights)
            """,
            {'login':login, "password": password, "rights": rights})
        db.commit()

        return self.cursor.lastrowid
    
    def login(self, login: str, password: bytes) -> object:
        """
            Logging
            -----------
            Parameters
            login : str
            password : str
            -----------
            return object
        """
        self.cursor.execute(
            """
                SELECT id, login, password FROM users
                WHERE login = :login AND password = :password
            """, 
            {"login": login, "password": password})

        return self.cursor.fetchone()
    
    def getPassword(self, login: str) -> bytes:
        """
            Getting encrypted password
            -----------
            Parameters
            login : str
            -----------
            return bytes
        """
        self.cursor.execute(
            """
                SELECT login, password FROM users
                WHERE login = :login
            """,
            {"login": login})
        return self.cursor.fetchone()
    
    def scoreAmount(self, login: str) -> object:
        """
            Get score of user, rights
            -----------
            Parameters
            login : str
            -----------
            return object
        """
        self.cursor.execute(
            """
                SELECT login, score FROM users
                WHERE login = :login
            """, 
            {"login": login})

        return self.cursor.fetchone()

    def loginName(self, id: str) -> object:
        """
            Get id, login from db
            -----------
            Parameters
            id : str
            -----------
            return object
        """
        self.cursor.execute(
            """
                SELECT id, login FROM users
                WHERE id = :id
            """, 
            {"id": id})

        return self.cursor.fetchone()

    def highScoreUpdate(self, score: int, id: str) -> int:
        """
            Update High Score of user
            -----------
            Parameters
            score : int
            id : str
            -----------
            return int
        """
        self.cursor.execute(
            """
                UPDATE users
                SET score = :score
                WHERE id = :id
            """,
            {'score':score, 'id':id})
        db.commit()

        return self.cursor.lastrowid

    def scoreInsert(self, id: str, score: int, date: str, time: str) -> int:
        """
            Insert score data of user
            -----------
            Parameters
            id : str
            score : int
            date : str
            time : str
            -----------
            return int
        """
        self.cursor.execute(
            """
                INSERT INTO stats (userID, score, date, time)
                VALUES (:id, :score, :date, :time)
            """,
            {'id': id, 'score': score, 'date': date, 'time': time})
        db.commit()

        return self.cursor.lastrowid

    def getStats(self, id: str) -> int:
            """
                Get Stats
                -----------
                Parameters
                id : str
                -----------
                return int
            """
            self.cursor.execute(
                """
                    SELECT score, date, time FROM stats
                    WHERE userID = :id
                """,
                {'id': id})
            
            return self.cursor.fetchall()
    
    def sortHighScores(self):
            """
                Sort and return HighScores
                -----------
                Parameters
                -----------
                return int
            """
            self.cursor.execute(
                 """
                    SELECT login, score FROM users
                    ORDER BY score DESC;
                 """)

            return self.cursor.fetchall()
    

    def getRights(self, login: str) -> object:
        """
            Get rights of user
            -----------
            Parameters
            login : str
            -----------
            return object
        """
        self.cursor.execute(
            """
                SELECT login, rights FROM users
                WHERE login = :login
            """, 
            {"login": login})

        return self.cursor.fetchone()
    
            
    def getAllRights(self) -> object:
        """
            Get rights of user
            -----------
            Parameters
            login : str
            -----------
            return object
        """
        self.cursor.execute(
            """
                SELECT login, rights FROM users
            """)

        return self.cursor.fetchall()
    
    def changeRoles(self, login: str, role: str) -> object:
        """
            Changing roles of the user
            -----------
            Parameters
            login : str
            role : str
            -----------
            return object
        """
        self.cursor.execute(
            """
            UPDATE users
            SET rights = :role
            WHERE login = :login

            """,
            {"login":login, "role": role})
        db.commit()

        return self.cursor.lastrowid

    def insertErrors(self, user_id: int, error: str, fixed: int) -> object:
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
        self.cursor.execute(
            """
                INSERT INTO error_list (user_id, errors, fixed)
                SELECT :user_id, :error, :fixed
                WHERE NOT EXISTS (
                    SELECT 1 FROM error_list WHERE errors = :error AND user_id = :user_id)
            """,
            {"user_id": user_id, "error": error, "fixed": fixed})
        db.commit()
        return self.cursor.lastrowid
    
    def getError(self, user_id: int) -> object:
        """
            Getting Errors by user_id
            -----------
            Parameters
            user_id : int
            -----------
            return object
        """
        self.cursor.execute(
            """
                SELECT errors, fixed FROM error_list
                WHERE user_id = :user_id
            """,
            {"user_id": user_id})
        return self.cursor.fetchall()
    

    def updateErrors(self, user_id: int, error: str, fixed: int) -> object:
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
        self.cursor.execute(
            """
                UPDATE error_list
                SET fixed = :fixed
                WHERE user_id = :user_id AND errors = :error
            """,
            {"user_id":user_id, "error": error, "fixed": fixed})
        db.commit()

        return self.cursor.lastrowid
    

    def postRequests(self, login: str, request: str) -> object:
        """
            Update requests column
            -----------
            Parameters
            login : str
            request: str
            -----------
            return object
        """
        self.cursor.execute(
            """
                UPDATE users
                SET request = :request
                WHERE login = :login
            """,
            {"login":login,"request": request})
        db.commit()


    def getAllRequests(self) -> object:
        """
            Get requests of user
            -----------
            Parameters
            -----------
            return object
        """
        self.cursor.execute(
            """
                SELECT request FROM users
            """)

        return self.cursor.fetchall()

    def getReq(self, login: str) -> object:
        """
            Get requests by login
            -----------
            Parameters
            login : str
            -----------
            return object
        """

        self.cursor.execute(
            """
                SELECT request FROM users
                WHERE login=:login
            """,
            {"login":login})
        return self.cursor.fetchone()
    


    def setNull(self, login: str) -> object:
        """
            Set requests to null by login
            -----------
            Parameters
            login : str
            -----------
            return object
        """

        self.cursor.execute(
            """
                UPDATE users set request = NULL
                WHERE login =:login
            """,
            {"login":login})
        db.commit()
        
        

    def jsInjectProtection(self, login: str):
        """
            JS inject Protection
            -----------
            Parameters
            login : str
            -----------
            return object
        """
        login = login\
            .replace("<", "&lt;")\
            .replace(">", "&gt;")\
            .replace('"', "&quot;")\
            .replace("'", "&#39;")
        return login
    

    def htmlDecrypt(self, login: str):
        login = login\
            .replace("&lt;", "<")\
            .replace("&gt;", ">")\
            .replace("&quot;", '"')\
            .replace("&#39;", "'")\
            .replace("%22", '"')
        return login

