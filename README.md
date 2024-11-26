# Socialize - Anonymous Social Media Platform

A modern, privacy-focused social media platform that integrates Calvin Chimes news and anonymous messaging.

## Features

### Core Features
- 🔒 Anonymous user profiles with randomly generated names
- 📝 Create, like, and retweet posts
- 🔄 Real-time updates for likes and retweets
- 🌐 Follow other users anonymously
- 📰 Integration with Calvin Chimes news
- 💬 Anonymous messaging system

### News Integration
- Automatic fetching of Calvin Chimes articles
- Trending news categories
- Article summaries and previews
- Direct links to full articles

### Messaging System
- Private messaging between users
- Anonymous conversations
- Real-time message updates
- Conversation management

### UI/UX Features
- 🎨 Modern, clean interface
- 📱 Responsive design
- ⚡ Smooth animations
- 🌙 Consistent styling
- 🖼️ Profile picture customization
- 📊 News category statistics

## Tech Stack
- Backend: Flask
- Database: SQLAlchemy (SQLite)
- Frontend: Bootstrap 5
- Authentication: Flask-Login
- Forms: Flask-WTF
- Web Scraping: BeautifulSoup4, Requests

## Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/socialize.git
cd socialize
```

2. Create a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Initialize the database:
```bash
python3
>>> from app import db
>>> db.create_all()
>>> exit()
```

5. Run the application:
```bash
python3 app.py
```

The application will be available at `http://localhost:8080`

## Project Structure
```
socialize/
├── app.py                 # Main application file
├── static/               # Static files
│   ├── css/             # CSS styles
│   ├── js/              # JavaScript files
│   └── uploads/         # User uploads
│       └── profile_pics/ # Profile pictures
├── templates/           # HTML templates
├── instance/           # Database and instance-specific files
└── requirements.txt    # Python dependencies
```

## Recent Updates

### UI Improvements
- Added icons to navigation menu
- Improved profile picture display
- Enhanced dropdown menu styling
- Added smooth animations for interactions

### News Integration
- Added trending news categories
- Improved article fetching reliability
- Enhanced error handling for web scraping
- Added article count tracking

### Profile Management
- Improved profile picture upload system
- Added automatic cleanup of old profile pictures
- Enhanced error handling for file uploads
- Added proper CSRF protection

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

## License
This project is licensed under the MIT License - see the LICENSE file for details.
