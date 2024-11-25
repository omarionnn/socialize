from app import app, db, User, bcrypt

def init_test_db():
    with app.app_context():
        # Drop all existing tables
        db.drop_all()
        # Create all tables
        db.create_all()
        
        # Create test users
        test_users = [
            {
                'username': 'testuser1',
                'email': 'test1@example.com',
                'password': 'password123'
            },
            {
                'username': 'testuser2',
                'email': 'test2@example.com',
                'password': 'password123'
            }
        ]
        
        for user_data in test_users:
            hashed_password = bcrypt.generate_password_hash(user_data['password']).decode('utf-8')
            user = User(
                username=user_data['username'],
                email=user_data['email'],
                password=hashed_password
            )
            db.session.add(user)
        
        # Commit the changes
        db.session.commit()
        print("Test database initialized with test users!")

if __name__ == '__main__':
    init_test_db()
