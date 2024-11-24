# Socialize

A modern social networking platform built with Flask and Bootstrap 5, featuring real-time interactions and a clean, responsive design. Connect with friends, share thoughts, and engage with your community.

## Features

### User Management
- User registration with email verification
- Secure authentication with password hashing
- User profiles with following/follower statistics
- User discovery feed

### Post Management
- Create posts with 280-character limit
- Real-time character count
- Timeline view of posts from followed users
- Personal profile with post history

### Social Interactions
- Follow/unfollow other users
- Like/unlike posts with real-time updates
- Repost functionality
- User discovery sidebar

### User Interface
- Clean, modern Bootstrap 5 design
- Responsive layout for all devices
- Interactive buttons with hover effects
- Real-time updates using AJAX
- Font Awesome icons for better visual feedback

### Direct Messaging System
- Real-time private messaging between users
- Conversation management with unread indicators
- Read receipts and message timestamps
- Real-time message updates (3-second polling)
- Multi-user conversation support
- Message threading with sender/receiver bubbles

## Technology Stack

- **Backend**: Python 3.x with Flask 2.2.5
- **Database**: SQLite with SQLAlchemy ORM
- **Frontend**: 
  - HTML5
  - CSS3 with Bootstrap 5
  - JavaScript with jQuery
- **Authentication**: Flask-Login, Flask-Bcrypt
- **Forms**: Flask-WTF
- **Additional**: Font Awesome for icons

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd twitter_mod
```

2. Create and activate a virtual environment:
```bash
# On macOS/Linux:
python3 -m venv venv
source venv/bin/activate

# On Windows:
python -m venv venv
venv\Scripts\activate
```

3. Install required packages:
```bash
pip install -r requirements.txt
```

4. Initialize the database:
```bash
python3
>>> from app import app, db
>>> with app.app_context():
...     db.create_all()
>>> exit()
```

## Running the Application

1. Start the Flask development server:
```bash
python3 app.py
```

2. Open your web browser and navigate to:
```
http://localhost:8000
```

## Testing the Application

1. **Create Test Users**:
   - Register two test accounts:
     - User 1: testuser1@example.com
     - User 2: testuser2@example.com

2. **Test Post Functionality**:
   - Log in as testuser1
   - Create several posts
   - Verify 280-character limit
   - Check post appearance in timeline

3. **Test Social Features**:
   - Log in as testuser2
   - Find testuser1 in the "Discover Users" sidebar
   - Follow testuser1
   - Like and repost testuser1's posts
   - Verify that testuser1's posts appear in testuser2's timeline

4. **Test User Interface**:
   - Verify responsive design on different screen sizes
   - Check real-time updates of like/repost counts
   - Test navigation between profiles and home page

5. **Testing the Messaging System**

1. **Initial Setup**:
   - Register two test accounts (if not already done)
   - Log in with the first account
   - Navigate to Messages section
   - Click "New Message"
   - Select the second user as recipient

2. **Basic Messaging**:
   - Send a test message from User 1
   - Log in as User 2 in a different browser/incognito window
   - Verify message received
   - Send reply from User 2
   - Check real-time updates on both ends

3. **Read Receipts**:
   - As User 1, send a new message
   - Note the single check mark (✓)
   - Log in as User 2 and open the conversation
   - Verify the check mark changes to double (✓✓)

4. **Unread Messages**:
   - Log out User 2
   - Send multiple messages as User 1
   - Log back in as User 2
   - Verify unread message counter in navigation
   - Check counter disappears after reading

5. **Edge Cases**:
   - Test empty messages (should be prevented)
   - Try long messages
   - Test rapid message sending
   - Verify proper message ordering
   - Check timestamp accuracy

## Project Structure

```
twitter_mod/
├── app.py              # Main Flask application
├── requirements.txt    # Python dependencies
├── static/
│   ├── style.css      # Custom CSS styles
│   └── main.js        # JavaScript for interactions
├── templates/
│   ├── base.html      # Base template with navigation
│   ├── home.html      # Home page with post feed
│   ├── login.html     # Login form
│   ├── register.html  # Registration form
│   └── profile.html   # User profile page
└── README.md          # Project documentation
```

## Security Features

- Password hashing using Bcrypt
- CSRF protection on all forms
- Secure session management
- SQL injection protection via SQLAlchemy
- XSS protection via template escaping

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## Future Enhancements

- Email notifications
- Hashtag support
- Media uploads (images, videos)
- Advanced search functionality
- User verification system
- Mobile app using the Flask backend as an API

## Troubleshooting

### Common Issues

1. **Port 8000 Already in Use**:
   ```bash
   # Check what's using the port
   lsof -i :8000
   # Kill the process
   kill -9 <PID>
   ```

2. **Database Issues**:
   ```bash
   # Reset the database
   rm instance/twitter.db
   python3
   >>> from app import app, db
   >>> with app.app_context():
   ...     db.create_all()
   ```

3. **Static Files Not Loading**:
   - Clear browser cache
   - Verify file paths in templates
   - Check Flask debug logs

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Flask documentation and community
- Bootstrap team for the excellent UI framework
- Font Awesome for the comprehensive icon set
