import os
import sys
from sqlalchemy import text

# Add the parent directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db

def upgrade():
    with app.app_context():
        # Create polls table
        with db.engine.connect() as conn:
            conn.execute(text('''
                CREATE TABLE IF NOT EXISTS poll (
                    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                    question VARCHAR(280) NOT NULL,
                    option1 VARCHAR(140) NOT NULL,
                    option2 VARCHAR(140) NOT NULL,
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    user_id INTEGER NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES user(id)
                )
            '''))
            
            # Create votes table
            conn.execute(text('''
                CREATE TABLE IF NOT EXISTS vote (
                    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                    poll_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    choice INTEGER NOT NULL,
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(poll_id) REFERENCES poll(id),
                    FOREIGN KEY(user_id) REFERENCES user(id),
                    UNIQUE(poll_id, user_id)
                )
            '''))
            
            conn.commit()
            print("Successfully created poll and vote tables!")

if __name__ == '__main__':
    upgrade()
