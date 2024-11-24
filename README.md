# Socialize

A modern social networking platform built with Flask and Bootstrap 5, featuring real-time interactions, robust security, and a clean, responsive design. Connect with friends, share thoughts, and engage with your community.

## Features

### User Management
- Secure user registration with email and username validation
- Enhanced authentication with password hashing using Bcrypt
- Comprehensive CSRF protection across all forms
- User profiles with following/follower system
- Duplicate email/username prevention
- User discovery feed

### Post Management
- Create posts with 280-character limit
- Real-time character count
- Timeline view of posts from followed users
- Personal profile with post history
- Image upload support for posts
- Hashtag extraction and linking

### Social Interactions
- Follow/unfollow system with proper validation
- Like/unlike posts with real-time updates
- Repost functionality
- User discovery sidebar
- Flash messages for user feedback

### User Interface
- Clean, modern Bootstrap 5 design
- Responsive layout for all devices
- Interactive buttons with hover effects
- Real-time updates using AJAX
- Font Awesome icons for better visual feedback
- Profile picture and cover photo upload

### Direct Messaging System
- Real-time private messaging between users
- Conversation management with unread indicators
- Read receipts and message timestamps
- Real-time message updates (3-second polling)
- Multi-user conversation support
- Message threading with sender/receiver bubbles

## Security Features
- CSRF protection on all forms using Flask-WTF
- Password hashing using Bcrypt
- Secure session management
- SQL injection protection via SQLAlchemy
- XSS protection via template escaping
- Proper error handling and user feedback
- Input validation and sanitization
- Duplicate registration prevention
- Secure file upload handling

## Technology Stack

- **Backend**: Python 3.x with Flask 2.2.5
- **Database**: SQLite with SQLAlchemy ORM
- **Frontend**: 
  - HTML5
  - CSS3 with Bootstrap 5
  - JavaScript with jQuery
- **Security**: 
  - Flask-Login for session management
  - Flask-Bcrypt for password hashing
  - Flask-WTF for CSRF protection
- **Forms**: WTForms with custom validators
- **Additional**: Font Awesome for icons

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd twitter_mod
```

2. Create and activate a virtual environment:
```bash
# Create virtual environment
python3 -m venv venv

# Activate on macOS/Linux:
source venv/bin/activate

# Activate on Windows:
venv\Scripts\activate
```

3. Install required packages:
```bash
# Upgrade pip first
python -m pip install --upgrade pip

# Install requirements
pip install -r requirements.txt
```

4. Set up environment variables:
```bash
# On macOS/Linux:
export FLASK_APP=app.py
export FLASK_ENV=development

# On Windows (Command Prompt):
set FLASK_APP=app.py
set FLASK_ENV=development

# On Windows (PowerShell):
$env:FLASK_APP = "app.py"
$env:FLASK_ENV = "development"
```

5. Initialize the database:
```bash
# Start Python interactive shell
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

### 1. User Registration and Authentication
- Register a new account with email and username
- Try registering with an existing email (should fail)
- Try registering with an existing username (should fail)
- Test login with correct and incorrect credentials
- Test password reset functionality

### 2. Profile Management
- Upload a profile picture
- Upload a cover photo
- Edit profile information
- Verify image upload size limits
- Check image format restrictions

### 3. Social Features
1. **Follow System Testing**:
   - Create two test accounts
   - Log in as User A
   - Visit User B's profile
   - Test follow button
   - Verify follower count updates
   - Test unfollow functionality
   - Try to follow yourself (should be prevented)

2. **Post Interaction Testing**:
   - Create posts with different lengths
   - Test character limit
   - Like/unlike posts
   - Repost functionality
   - Verify real-time updates

### 4. Direct Messaging
1. **Basic Messaging**:
   - Start new conversation
   - Send messages between users
   - Verify real-time updates
   - Check read receipts
   - Test unread message indicators

2. **Edge Cases**:
   - Send empty messages (should be prevented)
   - Test message length limits
   - Verify proper message ordering
   - Check timestamp accuracy

## Project Structure

```
twitter_mod/
├── app.py              # Main Flask application
├── requirements.txt    # Python dependencies
├── static/
│   ├── css/           # CSS stylesheets
│   │   └── style.css  # Custom styles
│   ├── js/            # JavaScript files
│   │   └── main.js    # Main JS functionality
│   └── uploads/       # User uploads directory
│       ├── avatars/   # Profile pictures
│       └── posts/     # Post images
├── templates/
│   ├── base.html      # Base template
│   ├── home.html      # Home feed
│   ├── login.html     # Login page
│   ├── register.html  # Registration page
│   ├── profile.html   # User profile
│   └── messages.html  # Messaging interface
└── README.md          # Documentation
```

## Troubleshooting

### Common Issues and Solutions

1. **Database Errors**:
   ```bash
   # Reset the database
   python3
   >>> from app import app, db
   >>> with app.app_context():
   ...     db.drop_all()
   ...     db.create_all()
   >>> exit()
   ```

2. **Package Installation Issues**:
   ```bash
   # Upgrade pip
   python -m pip install --upgrade pip
   
   # Clean install requirements
   pip uninstall -r requirements.txt -y
   pip install -r requirements.txt
   ```

3. **File Upload Issues**:
   - Check folder permissions
   - Verify upload directory exists
   - Ensure proper file extensions

4. **Server Won't Start**:
   - Check if port 8000 is in use
   - Verify virtual environment is activated
   - Confirm all requirements are installed

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
