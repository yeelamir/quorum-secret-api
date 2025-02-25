from typing import List
import pymysql
from pymysql.cursors import DictCursor
import datetime
from db_layer.entities.secret import Secret
from db_layer.entities.user import User, User_id_name



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
                    SELECT us.SecretId, us.DecryptRequest, us.IsOwner, s.Name, s.Quorum, s.Comments, s.StartingDate,
                    COUNT(DISTINCT us2.UserId) AS NDecryptRequest
                    FROM quorum_secrets.usersecret us
                    JOIN quorum_secrets.secrets s on s.Id = us.SecretId
                    LEFT JOIN quorum_secrets.usersecret us2 ON s.Id = us2.SecretId AND us2.DecryptRequest = 1  
                    WHERE us.UserId = %s
                    GROUP BY us.SecretId, us.DecryptRequest, us.IsOwner, s.Name, s.Quorum, s.Comments, s.StartingDate;
                """
                self.mycursor.execute(sql, (user_id,))
                all_secrets = self.mycursor.fetchall()
                return all_secrets
            except Exception as e:
                print(f"An unexpected error occurred: {e}")


    def get_secret_by_name(self, name: str):
        try:
            sql = "SELECT * FROM secrets WHERE Name = %s;"
            self.mycursor.execute(sql, name)
            return self.mycursor.fetchone()
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

    def get_user_publickey(self, id: int):
        try:
            sql = "SELECT PublicKey FROM users WHERE Id = %s;"
            self.mycursor.execute(sql, id)
            return self.mycursor.fetchone()
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

    def insert_secret(self, quorum: int, cipher: bytearray, name: str, comments: str, starting_date: datetime.datetime) -> int:
        try:
            sql = "INSERT INTO secrets (`Quorum`, `Cipher`, `Name`, `Comments`, `StartingDate`) VALUES (%s, %s, %s, %s, %s);"
            val = (quorum, cipher, name, comments, starting_date)
            self.mycursor.execute(sql, val)
            self.mydb.commit()
            new_secret_id = self.mycursor.lastrowid  # Get the ID of the newly inserted row
            print("record inserted.", new_secret_id)
            return new_secret_id
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            return -1

    def get_users(self) -> List[User_id_name]:
        try:
            sql = """
                SELECT Id, Username
                FROM quorum_secrets.users;
            """
            self.mycursor.execute(sql)
            all_users = self.mycursor.fetchall()
            return all_users
        
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

    def get_secret_users(self, secret_id: int) -> List[User_id_name]:
        try:
            sql = """
                SELECT us.UserId, s.Username
                FROM quorum_secrets.usersecret us
                JOIN quorum_secrets.users s on s.Id = us.UserId
                WHERE us.SecretId = %s;
            """
            self.mycursor.execute(sql, (secret_id,))
            all_users = self.mycursor.fetchall()
            return all_users
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






