import unittest
from app import app, db, User, Poll, Vote, bcrypt
from flask_login import current_user
from datetime import datetime

class SocializeTests(unittest.TestCase):
    def setUp(self):
        # Configure test database
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
        app.config['WTF_CSRF_ENABLED'] = False  # Disable CSRF for testing
        app.config['TESTING'] = True
        self.client = app.test_client()
        
        # Create test database and tables
        with app.app_context():
            db.create_all()
    
    def tearDown(self):
        # Remove test database
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def test_registration(self):
        """Test user registration"""
        with app.app_context():
            # Test valid registration
            response = self.client.post('/register', data={
                'username': 'testuser',
                'email': 'test@example.com',
                'password': 'password123',
                'confirm_password': 'password123'
            }, follow_redirects=True)
            self.assertIn(b'Account created successfully', response.data)
            
            # Test duplicate username
            response = self.client.post('/register', data={
                'username': 'testuser',
                'email': 'test2@example.com',
                'password': 'password123',
                'confirm_password': 'password123'
            }, follow_redirects=True)
            self.assertIn(b'Username already exists', response.data)

    def test_login_logout(self):
        """Test login and logout functionality"""
        with app.app_context():
            # Create test user with hashed password
            hashed_password = bcrypt.generate_password_hash('password123').decode('utf-8')
            user = User(username='testuser', email='test@example.com', 
                       password=hashed_password, anonymous_name='Anonymous1234')
            db.session.add(user)
            db.session.commit()
            
            # Test login
            response = self.client.post('/login', data={
                'email': 'test@example.com',
                'password': 'password123'
            }, follow_redirects=True)
            self.assertIn(b'Welcome back', response.data)
            
            # Test logout
            response = self.client.get('/logout', follow_redirects=True)
            self.assertIn(b'You have been logged out', response.data)

    def test_poll_creation(self):
        """Test poll creation and viewing"""
        with app.app_context():
            # Create test user with hashed password
            hashed_password = bcrypt.generate_password_hash('password123').decode('utf-8')
            user = User(username='testuser', email='test@example.com', 
                       password=hashed_password, anonymous_name='Anonymous1234')
            db.session.add(user)
            db.session.commit()
            
            # Login
            self.client.post('/login', data={
                'email': 'test@example.com',
                'password': 'password123'
            })
            
            # Create poll
            response = self.client.post('/create_poll', data={
                'question': 'Test Poll?',
                'option1': 'Yes',
                'option2': 'No'
            }, follow_redirects=True)
            self.assertIn(b'Poll created successfully', response.data)
            
            # Check if poll exists in database
            poll = Poll.query.filter_by(question='Test Poll?').first()
            self.assertIsNotNone(poll)
            self.assertEqual(poll.option1, 'Yes')
            self.assertEqual(poll.option2, 'No')

    def test_poll_voting(self):
        """Test poll voting functionality"""
        with app.app_context():
            # Create test user with hashed password
            hashed_password = bcrypt.generate_password_hash('password123').decode('utf-8')
            user = User(username='testuser', email='test@example.com', 
                       password=hashed_password, anonymous_name='Anonymous1234')
            db.session.add(user)
            db.session.commit()
            
            # Create test poll
            poll = Poll(question='Test Poll?', option1='Yes', option2='No',
                       user_id=user.id)
            db.session.add(poll)
            db.session.commit()
            
            # Login
            self.client.post('/login', data={
                'email': 'test@example.com',
                'password': 'password123'
            })
            
            # Test voting
            response = self.client.post(f'/vote/{poll.id}/1', 
                                      data={'csrf_token': 'test'}, 
                                      follow_redirects=True)
            self.assertEqual(response.status_code, 200)
            
            # Verify vote was recorded
            vote = Vote.query.filter_by(poll_id=poll.id, user_id=user.id).first()
            self.assertIsNotNone(vote)
            self.assertEqual(vote.choice, 1)
            
            # Test duplicate voting
            response = self.client.post(f'/vote/{poll.id}/2', 
                                      data={'csrf_token': 'test'}, 
                                      follow_redirects=True)
            self.assertIn(b'already voted', response.data.lower())

    def test_anonymous_names(self):
        """Test anonymous name generation and display"""
        with app.app_context():
            # Create multiple users and verify unique anonymous names
            usernames = []
            for i in range(3):
                hashed_password = bcrypt.generate_password_hash('password123').decode('utf-8')
                user = User(username=f'testuser{i}', 
                          email=f'test{i}@example.com',
                          password=hashed_password)
                db.session.add(user)
                db.session.commit()
                
                self.assertIsNotNone(user.anonymous_name)
                self.assertNotIn(user.anonymous_name, usernames)
                usernames.append(user.anonymous_name)

if __name__ == '__main__':
    unittest.main()
