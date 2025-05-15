import os
from db_layer.db_querries import data_access_layer


data_access_layer_instance = data_access_layer(
    db_host=os.getenv("QUORUM_APP_DB_HOST", "localhost"),
    db_user=os.getenv("QUORUM_APP_DB_USER", "root"),
    db_password=os.getenv("QUORUM_APP_DB_PASSWORD", "abc123"),
    db_name=os.getenv("QUORUM_APP_DB_NAME", "quorum_secrets")
)

def get_data_access_layer():
    return data_access_layer_instance
