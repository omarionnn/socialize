import os
import sys
import random
from sqlalchemy import text

# Add the parent directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db, User

def upgrade():
    with app.app_context():
        # Add the new column without UNIQUE constraint first
        with db.engine.connect() as conn:
            # Add the column
            conn.execute(text('ALTER TABLE user ADD COLUMN anonymous_name VARCHAR(20)'))
            
            # Create a temporary table with the desired schema
            conn.execute(text('''
                CREATE TABLE user_new (
                    id INTEGER NOT NULL PRIMARY KEY,
                    username VARCHAR(20) NOT NULL UNIQUE,
                    email VARCHAR(120) NOT NULL UNIQUE,
                    password VARCHAR(60) NOT NULL,
                    profile_pic VARCHAR(120) NOT NULL,
                    anonymous_name VARCHAR(20) UNIQUE,
                    bio VARCHAR(500),
                    cover_photo VARCHAR(100),
                    is_verified BOOLEAN
                )
            '''))
            
            # Copy data to the new table
            conn.execute(text('''
                INSERT INTO user_new 
                SELECT id, username, email, password, profile_pic, anonymous_name, bio, cover_photo, is_verified 
                FROM user
            '''))
            
            # Drop the old table
            conn.execute(text('DROP TABLE user'))
            
            # Rename the new table
            conn.execute(text('ALTER TABLE user_new RENAME TO user'))
            
            conn.commit()
        
        # Update existing users with random anonymous names
        users = User.query.all()
        used_names = set()
        
        for user in users:
            while True:
                anonymous_name = f"Anonymous{random.randint(1000, 9999)}"
                if anonymous_name not in used_names:
                    used_names.add(anonymous_name)
                    user.anonymous_name = anonymous_name
                    break
        
        db.session.commit()
        print("Successfully added anonymous names to all users!")

if __name__ == '__main__':
    upgrade()
