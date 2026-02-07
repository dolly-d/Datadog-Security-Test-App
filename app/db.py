from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from settings import settings

engine = create_engine(settings.database_url, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)

def init_db():
    # Simple table for demo. (Avoid migrations for lab simplicity.)
    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS notes (
                id SERIAL PRIMARY KEY,
                owner TEXT NOT NULL,
                body TEXT NOT NULL
            );
        """))
        # seed a row
        conn.execute(text("""
            INSERT INTO notes (owner, body)
            SELECT 'admin', 'top secret note'
            WHERE NOT EXISTS (SELECT 1 FROM notes WHERE owner='admin');
        """))
