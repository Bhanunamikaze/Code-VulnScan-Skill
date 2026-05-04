# BENCHMARK: secrets - database_connection_string
# WARNING: This file contains a fake DB URL for benchmark testing only

import os

DB_URL = "postgresql://admin:s3cr3tp@ss@localhost:5432/mydb"
REDIS_URL = "redis://:r3dis_p@ssw0rd@localhost:6379/0"


def get_db_engine():
    from sqlalchemy import create_engine
    url = os.environ.get("DATABASE_URL", DB_URL)
    return create_engine(url)
