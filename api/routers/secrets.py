# api/routers/secrets.py
import base64
import datetime
from typing import List
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from db_layer.db_accessor import get_data_access_layer
from db_layer.entities.secret import NewSecret, Secret
from encryption import aes, rsa


router = APIRouter(
    prefix="/secrets",
    tags=["Secrets"]
)

@router.post("", status_code=201) # Define a response model
def insert_new_secret(request: Request, secret: NewSecret):
    secret_data = get_data_access_layer().get_secret_by_name([secret.name])
    if secret_data:
        return {"validation": False, "message": "Secret name already exists"}
    
    #Creating a new secret
    #1. Generate a random AES256 key and IV
    iv = aes.get_iv()
    aes_key = aes.get_secret_key()
    #2. Encrypt the secret with the AES256 key and store it in the Secrets table together with the metadata
    encrypted_secret = aes.encrypt_secret(secret.secret.encode('utf-8'), aes_key, iv)
    secret_id = get_data_access_layer().insert_secret(secret.quorum, encrypted_secret, secret.name, secret.comment, secret.starting_date, iv)
    #3. Encrypt the AES256 key with the public keys of the owner and the group members and store it in the UserSecret table
    user_id = request.state.user['user_id']
    owner_public_key = get_data_access_layer().get_user_publickey(user_id)
    owner_encrypted_key = rsa.encrypt(owner_public_key, aes_key)
    owner_encrypted_key_str = base64.b64encode(owner_encrypted_key).decode('utf-8')
    get_data_access_layer().insert_user_secret(user_id, secret_id, True, owner_encrypted_key_str)
    #4. Create the AES256 key shares for all the group members. Encrypt each share with the user public key and store it in the UserSecret table
    secret_shares = sss.split_secret(aes_key, len(secret.group_users), secret.quorum)

    for i, user in enumerate(secret.group_users):
        user_public_key = get_data_access_layer().get_user_publickey(user)
        secret_share_bytes = base64.b64decode(secret_shares[i])
        user_encrypted_share = rsa.encrypt(user_public_key, secret_share_bytes)
        user_encrypted_share_str = base64.b64encode(user_encrypted_share).decode('utf-8')
        get_data_access_layer().insert_user_secret(user, secret_id, False, user_encrypted_share_str)

    return {"validation": True, "message": "Secret inserted successfully!"}


# Get all the secrets for the user
@router.get("", response_model=List[Secret])
async def get_all_secrets_for_current_user(request: Request):
    try:
        # Get the user ID from the request state
        user_id = request.state.user['user_id']
        return get_data_access_layer().get_all_secrets(user_id)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")




# Get a secret by ID
@router.get("/{secret_id}", response_model=Secret)
async def get_secret_by_id(request: Request, secret_id: int):
    user_id = request.state.user['user_id']
    return get_data_access_layer().get_shared_secret_by_id(user_id, secret_id)



# Delete secret by ID - only the owner can delete it
@router.delete("/{secret_id}", status_code=200)
async def delete_secret_by_id(request: Request, secret_id: int):
    user_id = request.state.user['user_id']
    secret = get_data_access_layer().get_shared_secret_by_id(user_id, secret_id)
    if not secret:
        return {"validation": False, "message": "Secret not found"}
    if not secret['IsOwner']:
        return {"validation": False, "message": "You are not the owner of this secret"}

    get_data_access_layer().delete_secret_by_id(secret_id)

    return {"validation": True, "message": "Secret deleted successfully!"}



class PrivateKey(BaseModel):
    private_key: str

# Set the DecryptRequest for a secret
@router.patch("/set_decrypt_request/{secret_id}")
async def set_decrypt_request(request: Request, secret_id: int, decrypt_request: PrivateKey):
    user_id = request.state.user['user_id']
    secret_data = get_data_access_layer().get_shared_secret_by_id(user_id, secret_id)
    if not secret_data:
        return {"validation": False, "message": "Secret not found"}
    
    if secret_data['StartingDate'] is not None:
        starting_date = secret_data['StartingDate'].replace(tzinfo=datetime.timezone.utc)
        if datetime.datetime.now(datetime.timezone.utc) < starting_date:
            return {"validation": False, "message": "Secret is not available yet"}
    
    if secret_data['NDecryptRequest'] >= secret_data['Quorum']:
        return {"validation": False, "message": "Secret is already decrypted"}

    #Check if the quorum is reached
    quorum = secret_data['Quorum']
    n_decrypt_request = secret_data['NDecryptRequest']
    #Decrypt the secret share with the private key of the user
    #1. Get the secret share from the database
    secret_share = secret_data['SecretShare']
    #2. Decrypt the secret share with the private key of the user
    decrypted_secret_share = rsa.decrypt(decrypt_request.private_key, base64.b64decode(secret_share))

    # Update the secret share in the database with the decrypted secret share
    # and set the decrypt request to true
    get_data_access_layer().set_decrypt_request(user_id, secret_id, base64.b64encode(decrypted_secret_share))


    if n_decrypt_request == quorum -1:
        #Get all the secret shares that their decripy request is true from the database
        decrypted_secret_shares = [n['SecretShare'] for n in get_data_access_layer().get_decrypted_secret_shares(secret_id)]
        # Reconstruct the secret with the secret shares
        sss_secret = sss.reconstruct_secret(decrypted_secret_shares)

        #Decrypt the secret for all the users that the secret is shared with
        # Get the secret shares from the database
        secret_shares = get_data_access_layer().get_secret_shares(secret_id)
        # Decrypt the secret for all the users that the secret is shared with
        for share in secret_shares:
            user_id = share['UserId']
            encrypted_secret = rsa.encrypt(share['PublicKey'], sss_secret)
            # Update the encrypted secret in the database and delete the secret share
            get_data_access_layer().set_encrypted_secret(user_id, secret_id, base64.b64encode(encrypted_secret))
        
    return {"validation": True, "message": "Secret updated successfully!"}


# Get the secret content by ID - Available only for the secret owner or 
# if the secret is shared with the user and the number of decrypt requests is equal to the quorum
@router.post("/secret_content/{secret_id}")
async def set_decrypt_request(request: Request, secret_id: int, user_private_key: PrivateKey):
    user_id = request.state.user['user_id']
    secret_data = get_data_access_layer().get_shared_secret_by_id(user_id, secret_id)
    if not secret_data:
        return {"validation": False, "message": "Secret not found"}
    
    if secret_data['EncryptedSecret'] == None:
        return {"validation": False, "message": "Secret is not available yet"}
    
    #Decrypt the secret with the private key of the user
    aes_key = rsa.decrypt(user_private_key.private_key, base64.b64decode(secret_data['EncryptedSecret'])) 
    cipher_and_iv = get_data_access_layer().get_cipher_by_id(secret_id)
    #Decrypt the secret with the AES256 key and IV
    iv = cipher_and_iv['IV']  
    the_secret = aes.decrypt_secret(cipher_and_iv['Cipher'], aes_key, iv)
    return the_secret.decode('utf-8')

