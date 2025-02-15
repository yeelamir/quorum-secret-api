from typing import List
import pymysql
from pymysql.cursors import DictCursor

from db_layer.entities.secret import Secret


class db_querries:
    USERS_TABLE_FIELDS = {'Id': 0, 'PublicKey': 1, 'Username': 2, 'Salt': 3, 'PasswordHash': 4}

    def __init__(self):
        self.mydb = pymysql.connect(
            host="localhost",
            user="root",
            password="abc123",
            database="quorum_secrets"
        )
        self.mycursor = self.mydb.cursor(DictCursor)
        
    def insert_user(self, PublicKey: str, Username: str, Salt: str, PasswordHash: str):
        try:
            sql = "INSERT INTO users (`PublicKey`, `Username`, `Salt`, `PasswordHash`) VALUES (%s, %s, %s, %s);"
            val = (PublicKey, Username, Salt, PasswordHash)
            self.mycursor.execute(sql, val)
            self.mydb.commit()
            print(self.mycursor.rowcount, "record inserted.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

    def get_user_by_username(self, username: str):
        sql = "SELECT * FROM users WHERE Username = %s;"
        self.mycursor.execute(sql, username)
        return self.mycursor.fetchone()

    def get_all_secrets(self, user_id: int) -> List[Secret]:
        try:
            sql = """
                SELECT us.SecretId, us.DecryptRequest, us.IsOwner, s.Name, s.Quorum, s.Comments
                FROM quorum_secrets.usersecret us
                JOIN quorum_secrets.secrets s on s.Id = us.SecretId
                WHERE us.UserId = %s;
            """
            self.mycursor.execute(sql, (user_id,))
            all_secrets = self.mycursor.fetchall()
            return all_secrets
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

    def select_user(self, fields=None):
        if fields is None:
            self.mycursor.execute("SELECT * FROM users")
            return self.mycursor.fetchall()
        
        fields = [field for field in fields if field in self.USERS_TABLE_FIELDS.keys()]
    
        if not fields:
            raise ValueError("At least one valid field must be selected.")
        
        query = f"SELECT {', '.join(fields)} FROM users;"
        self.mycursor.execute(query)
        return self.mycursor.fetchall()






