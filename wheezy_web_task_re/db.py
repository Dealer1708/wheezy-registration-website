import sqlite3


class DataBase():
    def __init__(self):
        self.db = sqlite3.connect('data.db')
        self.db.row_factory = self.dict_factory

    def dict_factory(self, cursor, row):
        d = {}
        for idx, col in enumerate(cursor.description):
            d[col[0]] = row[idx]
        return d

    def change(self, sql_query: str, values: dict = {}):
        """
        Change data in tables
        -----------
        Parameters
        sql_query: str
        login : dic
        """
        self.cursor = self.db.cursor()
        self.cursor.execute(sql_query, values)
        self.db.commit()
        self.cursor.close()

    def select(
            self,
            sql_query: str,
            fetch_method: str = "one",
            key: str = None,
            values: dict = {}
        ):
        """
        Select data from tables
        -----------
        Parameters
        sql_query: str
        login : dict
        """
        self.cursor = self.db.cursor()
        self.cursor.execute(sql_query, values)
        if fetch_method == "all":
            result = self.cursor.fetchall()
            self.cursor.close()
            return result
        if not key:
            result = self.cursor.fetchone()
        else:
            result = self.cursor.fetchone()[key]
        self.cursor.close()
        return result