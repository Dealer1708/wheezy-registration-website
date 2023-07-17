import sqlite3

conn = sqlite3.connect('data.db')
cursor = conn.cursor()
print('Database changed successfully')
# cursor.execute(
#     """CREATE TABLE IF NOT EXISTS lalal(
#     id INTEGER PRIMARY KEY AUTOINCREMENT,
#     login TEXT NOT NULL,
#     password TEXT NOT NULL,
#     score INTEGER);"""
# )

# cursor.execute(
#     """
#         ALTER TABLE users
#         DROP COLUMN key;
#     """
# )

# cursor.execute(
#     """
#         CREATE TABLE IF NOT EXISTS stats(
#         id INTEGER PRIMARY KEY AUTOINCREMENT,
#         userID INTEGER,
#         score NOT NULL,
#         date TEXT NOT NULL,
#         time TEXT NOT NULL,
#         FOREIGN KEY (userID) REFERENCES users(id) ON DELETE CASCADE
#         );
#     """)
# cursor.execute("SELECT userID, score, date, time FROM stats WHERE userID = '63'")
# print(cursor.fetchall())
# cursor.execute(
#     """ALTER TABLE users
#     ADD rights TEXT;
#     """
# )




############## NEW #############

# cursor.execute(
#     """
#         CREATE TABLE IF NOT EXISTS error_list(
#         id INTEGER PRIMARY KEY AUTOINCREMENT,
#         user_id INTEGER,
#         errors NOT NULL,
#         fixed TEXT NOT NULL,
#         FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
#         );
#     """)

##################################


# new####
# cursor.execute(
#     """
#     ALTER TABLE users
#     ADD request TEXT;
#     """
# )


cursor.execute(
    """
    ALTER TABLE stats
    DROP COLUMN time;
    """
)