import os
from dotenv import load_dotenv
from falkordb import FalkorDB

load_dotenv()


def connect():
    # reads the address from .env; falls back to your laptop if nothing is set
    host = os.getenv('FALKORDB_HOST', 'localhost')
    port = int(os.getenv('FALKORDB_PORT', '6379'))
    user = os.getenv('FALKORDB_USERNAME') or None
    password = os.getenv('FALKORDB_PASSWORD') or None
    ssl = os.getenv('FALKORDB_SSL', '').lower() in ('1', 'true', 'yes')
    return FalkorDB(host=host, port=port, username=user,
                    password=password, ssl=ssl)
