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
    
    def sign_up(self, login: str, password: str) -> int:
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
                INSERT INTO users (login, password, score)
                VALUES (:login, :password, 0)
            """,
            {'login':login, "password": password})
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
            Get score of user
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
                    SELECT userID, score, date, time FROM stats
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
            





















# emailPattern = /(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])/;

