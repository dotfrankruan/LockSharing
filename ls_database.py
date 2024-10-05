#!/usr/bin/env python3
"""User is allowed to choose any database that is available in Python."""

DATABASE_TYPE = "sqlite3" 
SQLITE3_NAME = "db.sqlite3"

def execute(command, ret=False):
    if DATABASE_TYPE == "sqlite3":
        import sqlite3
        conn = sqlite3.connect("db.sqlite3")
        cursor = conn.cursor()
    else:
        # Database not supported
        raise Exception("Database is not supported.")
    cursor.execute(command)
    if ret == True:
        fetches = cursor.fetchall()
    conn.commit()
    conn.close()
    if ret == True:
        return fetches
    
def init_db():
    execute('''
            CREATE TABLE IF NOT EXISTS locksharing_pubkeys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                keyid TEXT NOT NULL,
                uid TEXT,
                keytext TEXT NOT NULL
            )
    ''')

