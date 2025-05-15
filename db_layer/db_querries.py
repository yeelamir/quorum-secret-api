import os
from typing import List, Dict, Any, Optional 
import pymysql
from pymysql.cursors import DictCursor
import datetime

from db_layer.entities.user import User_id_name

class data_access_layer:
    """
    A class to handle database operations for the Quorum Secrets application.
    This class provides methods to interact with the database, including inserting, updating,
    and retrieving user and secret information.
    """ 


    def __init__(self, db_host, db_user, db_password, db_name):
        self.db_config = {
            'host': db_host,
            'user': db_user,
            'password': db_password,
            'database': db_name,
            'cursorclass': DictCursor # Set DictCursor as default for connections
        }

    def _execute_query(self, sql: str, params: Optional[tuple] = None, fetch_one: bool = False, fetch_all: bool = False, is_insert: bool = False) -> Any:
        """
        Helper function to execute queries, managing connection and cursor.
        """
        try:
            with pymysql.connect(**self.db_config) as mydb:
                with mydb.cursor() as mycursor: # Cursor will be DictCursor due to db_config
                    mycursor.execute(sql, params)
                    if is_insert:
                        mydb.commit()
                        # print(mycursor.rowcount, "record inserted/affected.") # Optional: for debugging
                        return mycursor.lastrowid # For INSERT returning ID
                    elif fetch_one:
                        return mycursor.fetchone()
                    elif fetch_all:
                        return mycursor.fetchall()
                    else: # For UPDATE, DELETE, or DDL without specific return needs other than commit
                        mydb.commit()
                        # print(mycursor.rowcount, "record(s) affected.") # Optional: for debugging
                        return mycursor.rowcount 
        except pymysql.MySQLError as e: # More specific exception handling
            print(f"Database error occurred: {e}")
            # In a real app, you'd log this with a proper logger and potentially re-raise or return a specific error indicator
            raise # Re-raising the exception is often a good default
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            raise

    def insert_user(self, PublicKey: str, Username: str, Salt: str, PasswordHash: str) -> Optional[int]:
        """
        Inserts a new user into the 'users' table with the provided public key, username, salt, and password hash.

        Args:
            PublicKey (str): The public key associated with the user.
            Username (str): The username of the user.
            Salt (str): The cryptographic salt used for hashing the password.
            PasswordHash (str): The hashed password of the user.

        Returns:
            Optional[int]: Returns None. Optionally, could return the last inserted row ID if needed.
        """
        sql = "INSERT INTO users (`PublicKey`, `Username`, `Salt`, `PasswordHash`) VALUES (%s, %s, %s, %s);"
        val = (PublicKey, Username, Salt, PasswordHash)
        # is_insert flag will ensure commit and return lastrowid, though we don't use it here
        # For insert_user, typically you might want to know if it succeeded via rowcount if not lastrowid
        self._execute_query(sql, val, is_insert=True) # original code just printed rowcount
        print(f"User {Username} inserted.") # Keep similar print for now
        return None # Or return lastrowid if needed by caller

    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        sql = "SELECT * FROM users WHERE Username = %s;"
        return self._execute_query(sql, (username,), fetch_one=True)

    def get_all_secrets(self, user_id: int) -> List[Dict[str, Any]]: # Assuming Secret can be represented as Dict
        """
        Retrieves all secrets associated with a given user ID.
        Args:
            user_id (int): The ID of the user whose secrets are to be retrieved.
        Returns:
            List[Dict[str, Any]]: A list of dictionaries representing the secrets.
        """


        sql = """
            SELECT us.SecretId, us.DecryptRequest, us.IsOwner, s.Name, s.Quorum, s.Comments, s.StartingDate, us.SecretShare, us.EncryptedSecret,
            COUNT(DISTINCT us2.UserId) AS NDecryptRequest
            FROM quorum_secrets.usersecret us
            JOIN quorum_secrets.secrets s on s.Id = us.SecretId
            LEFT JOIN quorum_secrets.usersecret us2 ON s.Id = us2.SecretId AND us2.DecryptRequest = 1
            WHERE us.UserId = %s
            GROUP BY us.SecretId, us.DecryptRequest, us.IsOwner, s.Name, s.Quorum, s.Comments, s.StartingDate, us.SecretShare, us.EncryptedSecret;
        """
        return self._execute_query(sql, (user_id,), fetch_all=True) or []

    def get_secret_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        sql = "SELECT * FROM secrets WHERE Name = %s;"
        return self._execute_query(sql, (name,), fetch_one=True)

    def get_cipher_by_id(self, secret_id: int) -> Optional[Dict[str, Any]]: # Changed id to secret_id for clarity
        sql = "SELECT Cipher, IV FROM secrets WHERE Id = %s;"
        return self._execute_query(sql, (secret_id,), fetch_one=True)

    def get_user_publickey(self, user_id: int) -> Optional[str]: # Changed id to user_id
        sql = "SELECT PublicKey FROM users WHERE Id = %s;"
        result = self._execute_query(sql, (user_id,), fetch_one=True)
        return result['PublicKey'] if result else None

    def insert_secret(self, quorum: int, cipher: bytearray, name: str, comments: str, starting_date: datetime.datetime, iv : bytes) -> Optional[int]:
        sql = "INSERT INTO secrets (`Quorum`, `Cipher`, `Name`, `Comments`, `StartingDate`, `IV`) VALUES (%s, %s, %s, %s, %s, %s);"
        val = (quorum, cipher, name, comments, starting_date, iv)
        new_secret_id = self._execute_query(sql, val, is_insert=True)
        print("Secret record inserted.", new_secret_id)
        return new_secret_id

    def get_users(self) -> List[User_id_name]: 
        sql = "SELECT Id, Username FROM quorum_secrets.users;"
        return self._execute_query(sql, fetch_all=True) or []

    def insert_user_secret(self, user_id: int, secret_id: int, is_owner: bool, secret_data: str): # Renamed secret_share to secret_data
        if is_owner:
            sql = "INSERT INTO usersecret (`UserId`, `SecretId`, `IsOwner`, `EncryptedSecret`) VALUES (%s, %s, %s, %s);"
        else:
            sql = "INSERT INTO usersecret (`UserId`, `SecretId`, `IsOwner`, `SecretShare`) VALUES (%s, %s, %s, %s);"
        val = (user_id, secret_id, is_owner, secret_data)
        self._execute_query(sql, val, is_insert=True) # Use is_insert for commit
        # Original code didn't print, so keeping it that way

    def get_secret_users(self, secret_id: int) -> List[User_id_name]: 
        sql = """
            SELECT us.UserId, s.Username
            FROM quorum_secrets.usersecret us
            JOIN quorum_secrets.users s on s.Id = us.UserId
            WHERE us.SecretId = %s;
        """
        return self._execute_query(sql, (secret_id,), fetch_all=True) or []


    def get_shared_secret_by_id(self, user_id: int, secret_id: int) -> Optional[Dict[str, Any]]: # Assuming Secret can be Dict
        sql = """
            SELECT us.SecretId, us.DecryptRequest, us.IsOwner, s.Name, s.Quorum, s.Comments, s.StartingDate, us.SecretShare, us.EncryptedSecret,
            COUNT(DISTINCT us2.UserId) AS NDecryptRequest
            FROM quorum_secrets.usersecret us
            JOIN quorum_secrets.secrets s on s.Id = us.SecretId
            LEFT JOIN quorum_secrets.usersecret us2 ON s.Id = us2.SecretId AND us2.DecryptRequest = 1
            WHERE us.UserId = %s and us.SecretId = %s
            GROUP BY us.SecretId, us.DecryptRequest, us.IsOwner, s.Name, s.Quorum, s.Comments, s.StartingDate, us.SecretShare, us.EncryptedSecret;
        """
        return self._execute_query(sql, (user_id, secret_id), fetch_one=True)

    def set_decrypt_request(self, user_id : int, secret_id: int, decrypted_secret_share: str):
        sql = """
            UPDATE quorum_secrets.usersecret
            SET DecryptRequest = 1, SecretShare = %s
            WHERE UserId = %s AND SecretId = %s;
        """
        val = (decrypted_secret_share, user_id, secret_id)
        self._execute_query(sql, val) # Default action is commit for non-select/non-insert_returning_id

    def delete_secret_by_id(self, secret_id: int):
        sql = "DELETE FROM secrets WHERE Id = %s;"
        self._execute_query(sql, (secret_id,))

    def get_decrypted_secret_shares(self, secret_id: int) -> List[Dict[str, Any]]: # Returns a list of dicts
        sql = """
            SELECT us.SecretShare
            FROM quorum_secrets.usersecret us
            WHERE us.DecryptRequest = 1 AND us.SecretId = %s;
        """
        results = self._execute_query(sql, (secret_id,), fetch_all=True)
        return results or [] # Ensure list is returned

    def get_secret_shares_users_publickey(self, secret_id: int) -> List[Dict[str, Any]]: # Renamed for clarity, User_publickey implies UserId and PublicKey
        sql = """
            SELECT us.UserId, u.PublicKey
            FROM quorum_secrets.usersecret us
            JOIN quorum_secrets.users u on u.Id = us.UserId
            WHERE us.SecretId = %s;
        """
        return self._execute_query(sql, (secret_id,), fetch_all=True) or []

    def set_encrypted_secret(self, user_id: int, secret_id: int, encrypted_secret: str):
        sql = """
            UPDATE quorum_secrets.usersecret
            SET EncryptedSecret = %s, SecretShare = NULL
            WHERE UserId = %s AND SecretId = %s;
        """
        val = (encrypted_secret, user_id, secret_id)
        self._execute_query(sql, val)