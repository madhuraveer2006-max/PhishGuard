
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "phishguard.db"


def get_db_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    connection = get_db_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            url TEXT NOT NULL,
            status TEXT NOT NULL,
            risk TEXT NOT NULL,
            scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    connection.commit()
    connection.close()


if __name__ == "__main__":
    init_db()
    print("Database created successfully!")
