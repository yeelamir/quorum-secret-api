from typing import List
import pymysql
from pymysql.cursors import DictCursor
import datetime
from db_layer.entities.secret import Secret
from db_layer.entities.user import User, User_id_name, User_publickey


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
    
    # Get all secrets of a user by user_id. It will return the secrets if they exist and the user has access to them, otherwise None.
    # Notes:
    #  - The NDecryptRequest field is the number of users that have requested to decrypt the secret. 
    #  - It is calculated by counting the number of distinct users that have requested to decrypt the secret.
    def get_all_secrets(self, user_id: int) -> List[Secret]:
            try:
                sql = """
                    SELECT us.SecretId, us.DecryptRequest, us.IsOwner, s.Name, s.Quorum, s.Comments, s.StartingDate, us.SecretShare, us.EncryptedSecret,
                    COUNT(DISTINCT us2.UserId) AS NDecryptRequest
                    FROM quorum_secrets.usersecret us
                    JOIN quorum_secrets.secrets s on s.Id = us.SecretId
                    LEFT JOIN quorum_secrets.usersecret us2 ON s.Id = us2.SecretId AND us2.DecryptRequest = 1  
                    WHERE us.UserId = %s
                    GROUP BY us.SecretId, us.DecryptRequest, us.IsOwner, s.Name, s.Quorum, s.Comments, s.StartingDate, us.SecretShare, us.EncryptedSecret;
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

    def get_cipher_by_id(self, id: int):
        try:
            sql = "SELECT Cipher, IV FROM secrets WHERE Id = %s;"
            self.mycursor.execute(sql, id)
            return self.mycursor.fetchone()
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

    def get_user_publickey(self, id: int) -> str:
        try:
            sql = "SELECT PublicKey FROM users WHERE Id = %s;"
            self.mycursor.execute(sql, id)
            return self.mycursor.fetchone()['PublicKey']
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

    def insert_secret(self, quorum: int, cipher: bytearray, name: str, comments: str, starting_date: datetime.datetime, iv : bytes) -> int:
        try:
            sql = "INSERT INTO secrets (`Quorum`, `Cipher`, `Name`, `Comments`, `StartingDate`, `IV`) VALUES (%s, %s, %s, %s, %s, %s);"
            val = (quorum, cipher, name, comments, starting_date, iv)
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

    def insert_user_secret(self, user_id: int, secret_id: int, is_owner: bool, secret_share: str):
        try:
            if is_owner:
                sql = "INSERT INTO usersecret (`UserId`, `SecretId`, `IsOwner`, `EncryptedSecret`) VALUES (%s, %s, %s, %s);"
            else:
                sql = "INSERT INTO usersecret (`UserId`, `SecretId`, `IsOwner`, `SecretShare`) VALUES (%s, %s, %s, %s);"

            val = (user_id, secret_id, is_owner, secret_share)
            self.mycursor.execute(sql, val) 
            self.mydb.commit()

        except Exception as e:
            print(f"An unexpected error occurred: {e}")     

    # Get all users that have access to a secret by secret_id. 
    # It will return the users if they exist and have access to the secret, otherwise None.
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

    #Get a shared secret by user_id and secret_id. It will return the secret if it exists and the secret was shared 
    # with the given user, otherwise None.
    def get_shared_secret_by_id(self, user_id: int, secret_id: int) -> Secret:
            try:
                sql = """
                    SELECT us.SecretId, us.DecryptRequest, us.IsOwner, s.Name, s.Quorum, s.Comments, s.StartingDate, us.SecretShare, us.EncryptedSecret,
                    COUNT(DISTINCT us2.UserId) AS NDecryptRequest
                    FROM quorum_secrets.usersecret us
                    JOIN quorum_secrets.secrets s on s.Id = us.SecretId
                    LEFT JOIN quorum_secrets.usersecret us2 ON s.Id = us2.SecretId AND us2.DecryptRequest = 1  
                    WHERE us.UserId = %s and us.SecretId = %s
                    GROUP BY us.SecretId, us.DecryptRequest, us.IsOwner, s.Name, s.Quorum, s.Comments, s.StartingDate, us.SecretShare, us.EncryptedSecret;
                """
                self.mycursor.execute(sql, (user_id,secret_id,))
                all_secrets = self.mycursor.fetchone()
                return all_secrets
            except Exception as e:
                print(f"An unexpected error occurred: {e}")


    # Update the secret share in the database with the decrypted secret share
    # and set the decrypt request to true
    def set_decrypt_request(self, user_id : int, secret_id: int, decrypted_secret_share: str) :
        try:
            sql = """
                UPDATE quorum_secrets.usersecret
                SET DecryptRequest = 1, SecretShare = %s
                WHERE UserId = %s AND SecretId = %s;
            """
            val = (decrypted_secret_share, user_id, secret_id)
            self.mycursor.execute(sql, val)
            self.mydb.commit()
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

    def delete_secret_by_id(self, secret_id: int):
        try:
            sql = "DELETE FROM secrets WHERE Id = %s;"
            self.mycursor.execute(sql, (secret_id,))
            self.mydb.commit()
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

    def get_decrypted_secret_shares(self, secret_id: int) -> List[str]:
        try:
            sql = """
                SELECT us.SecretShare 
                FROM quorum_secrets.usersecret us
                WHERE us.DecryptRequest = 1 AND us.SecretId = %s;
            """
            self.mycursor.execute(sql, (secret_id,))
            all_secrets = self.mycursor.fetchall()
            return all_secrets
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

    def get_secret_shares(self, secret_id) -> List[User_publickey]:
        try:
            sql = """
                SELECT us.UserId, u.PublicKey
                FROM quorum_secrets.usersecret us
                join quorum_secrets.users u on u.Id = us.UserId
                WHERE us.SecretId = %s;
            """
            self.mycursor.execute(sql, (secret_id,))
            all_secrets = self.mycursor.fetchall()
            return all_secrets
        except Exception as e:
            print(f"An unexpected error occurred: {e}") 

    # Update the encrypted secret in the database and delete the secret share
    def set_encrypted_secret(self, user_id: int, secret_id: int, encrypted_secret: str) :
        try:
            sql = """
                UPDATE quorum_secrets.usersecret
                SET EncryptedSecret = %s, SecretShare = NULL
                WHERE UserId = %s AND SecretId = %s;
            """
            val = (encrypted_secret, user_id, secret_id)
            self.mycursor.execute(sql, val)
            self.mydb.commit()
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
        