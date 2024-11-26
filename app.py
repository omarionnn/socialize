from flask import Flask, render_template, url_for, flash, redirect, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
import os
import logging
from werkzeug.utils import secure_filename
import re
from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField
from wtforms.validators import DataRequired, Length, Email
import random
from sqlalchemy import func
import requests
from bs4 import BeautifulSoup
import time

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Get the absolute path to the instance directory
basedir = os.path.abspath(os.path.dirname(__file__))
instance_dir = os.path.join(basedir, 'instance')
db_path = os.path.join(instance_dir, 'twitter.db')

# Create instance directory if it doesn't exist
os.makedirs(instance_dir, exist_ok=True)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'  # Make sure this is set
csrf = CSRFProtect()
csrf.init_app(app)  # Initialize CSRF protection
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # 1 hour

# File upload configuration
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads', 'profile_pics')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create upload folders if they don't exist
os.makedirs(os.path.join(UPLOAD_FOLDER, 'profile_pics'), exist_ok=True)
os.makedirs(os.path.join(UPLOAD_FOLDER, 'cover_photos'), exist_ok=True)
os.makedirs(os.path.join(UPLOAD_FOLDER, 'post_images'), exist_ok=True)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

followers = db.Table('followers',
    db.Column('follower_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('followed_id', db.Integer, db.ForeignKey('user.id'))
)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    anonymous_name = db.Column(db.String(80), unique=True, nullable=False)
    profile_pic = db.Column(db.String(120), nullable=False, default='default.jpg')
    cover_photo = db.Column(db.String(120), nullable=False, default='default_cover.jpg')
    tweets = db.relationship('Tweet', backref='author', lazy=True)
    following = db.relationship(
        'User', secondary=followers,
        primaryjoin=(followers.c.follower_id == id),
        secondaryjoin=(followers.c.followed_id == id),
        backref=db.backref('followers', lazy='dynamic'),
        lazy='dynamic'
    )

    def __init__(self, *args, **kwargs):
        super(User, self).__init__(*args, **kwargs)
        if not self.anonymous_name:
            while True:
                anonymous_name = f"Anonymous{random.randint(1000, 9999)}"
                if not User.query.filter_by(anonymous_name=anonymous_name).first():
                    self.anonymous_name = anonymous_name
                    break

    def get_display_name(self):
        """Return the anonymous name for public display"""
        return self.anonymous_name

    def follow(self, user):
        if not self.is_following(user):
            self.following.append(user)

    def unfollow(self, user):
        if self.is_following(user):
            self.following.remove(user)

    def is_following(self, user):
        return self.following.filter(followers.c.followed_id == user.id).count() > 0

class Hashtag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    posts = db.relationship('Tweet', secondary='tweet_hashtags', backref='hashtags')
    
    def __repr__(self):
        return f'#{self.name}'

tweet_hashtags = db.Table('tweet_hashtags',
    db.Column('tweet_id', db.Integer, db.ForeignKey('tweet.id'), primary_key=True),
    db.Column('hashtag_id', db.Integer, db.ForeignKey('hashtag.id'), primary_key=True)
)

class Tweet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(280), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    image = db.Column(db.String(100))
    likes = db.relationship('Like', backref='tweet', lazy=True)
    retweets = db.relationship('Retweet', backref='tweet', lazy=True)

    def extract_hashtags(self):
        hashtag_pattern = r'#(\w+)'
        return re.findall(hashtag_pattern, self.content)

class Follow(db.Model):
    follower_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    followed_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    tweet_id = db.Column(db.Integer, db.ForeignKey('tweet.id'), nullable=False)

class Retweet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    tweet_id = db.Column(db.Integer, db.ForeignKey('tweet.id'), nullable=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversation.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

class Conversation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    messages = db.relationship('Message', backref='conversation', lazy='dynamic', order_by='Message.timestamp')
    participants = db.relationship('ConversationParticipants', backref='conversation', lazy=True)

class ConversationParticipants(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversation.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign Up')

class TweetForm(FlaskForm):
    content = StringField('Content', validators=[DataRequired(), Length(max=280)])
    submit = SubmitField('Post')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class FollowForm(FlaskForm):
    submit = SubmitField('Follow')

class MessageForm(FlaskForm):
    content = StringField('Message', validators=[DataRequired()])
    submit = SubmitField('Send')

class News(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    url = db.Column(db.String(500), nullable=False, unique=True)
    summary = db.Column(db.Text)
    image_url = db.Column(db.String(500))
    published_date = db.Column(db.DateTime, nullable=False)
    comments = db.relationship('NewsComment', backref='news', lazy=True)

class NewsComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    news_id = db.Column(db.Integer, db.ForeignKey('news.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class NewsCommentForm(FlaskForm):
    content = TextAreaField('Comment', validators=[DataRequired(), Length(min=1, max=500)])
    submit = SubmitField('Post Comment')

def get_trending_categories():
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get('https://calvinchimes.org', headers=headers, timeout=10)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Find the categories from the navigation menu
        categories = []
        nav_menu = soup.find('ul', class_='nav-menu')
        if nav_menu:
            category_items = nav_menu.find_all('li', class_='menu-item')
            for item in category_items:
                link = item.find('a')
                if link:
                    category = {
                        'name': link.text.strip(),
                        'url': link['href'],
                        'count': News.query.filter(News.url.like(f"%{link['href']}%")).count()
                    }
                    categories.append(category)
        
        # Sort by article count
        categories.sort(key=lambda x: x['count'], reverse=True)
        return categories[:5]  # Return top 5 categories
    except Exception as e:
        print(f"Error fetching categories: {str(e)}")
        return []

# Routes
@app.route('/')
@app.route('/home')
def home():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    if current_user.is_authenticated:
        followed_users = [user.id for user in current_user.following.all()]
        followed_users.append(current_user.id)
        tweets = Tweet.query.filter(Tweet.user_id.in_(followed_users)).order_by(Tweet.date_posted.desc())
    else:
        tweets = Tweet.query.order_by(Tweet.date_posted.desc())
    
    tweets = tweets.paginate(page=page, per_page=per_page)
    
    # Get trending categories for the sidebar
    trending_categories = get_trending_categories()
    
    if request.headers.get('HX-Request'):
        return render_template('_tweets.html', tweets=tweets)
    
    form = TweetForm()
    return render_template('home.html', tweets=tweets, form=form, trending_categories=trending_categories)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        try:
            username = request.form.get('username', '').strip()
            email = request.form.get('email', '').strip()
            password = request.form.get('password', '')
            confirm_password = request.form.get('confirm_password', '')

            # Validation
            if not all([username, email, password, confirm_password]):
                flash('All fields are required', 'danger')
                return redirect(url_for('register'))

            if len(username) < 3 or len(username) > 20:
                flash('Username must be between 3 and 20 characters', 'danger')
                return redirect(url_for('register'))

            if not re.match(r'^[a-zA-Z0-9_]+$', username):
                flash('Username can only contain letters, numbers, and underscores', 'danger')
                return redirect(url_for('register'))

            if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
                flash('Please enter a valid email address', 'danger')
                return redirect(url_for('register'))

            if password != confirm_password:
                flash('Passwords do not match', 'danger')
                return redirect(url_for('register'))

            if len(password) < 6:
                flash('Password must be at least 6 characters long', 'danger')
                return redirect(url_for('register'))

            # Check existing users
            if User.query.filter_by(username=username).first():
                flash('Username already exists', 'danger')
                return redirect(url_for('register'))

            if User.query.filter_by(email=email).first():
                flash('Email already exists', 'danger')
                return redirect(url_for('register'))

            # Generate unique anonymous name
            while True:
                anonymous_name = f"Anonymous{random.randint(1000, 9999)}"
                if not User.query.filter_by(anonymous_name=anonymous_name).first():
                    break

            # Create new user
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            user = User(
                username=username,
                email=email,
                password=hashed_password,
                anonymous_name=anonymous_name,
                profile_pic='default.jpg',
                cover_photo='default_cover.jpg'
            )
            
            db.session.add(user)
            db.session.commit()

            flash('Account created successfully! You can now log in', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            db.session.rollback()
            flash('An error occurred. Please try again.', 'danger')
            app.logger.error(f"Registration error: {str(e)}")
            return redirect(url_for('register'))

    return render_template('register.html', title='Register')

@app.route('/login', methods=['GET', 'POST'])
def login():
    logger.debug('Login route accessed')
    if current_user.is_authenticated:
        logger.debug('User already authenticated, redirecting to home')
        return redirect(url_for('home'))
    
    form = LoginForm()
    if form.validate_on_submit():
        logger.debug('Processing POST request')
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            logger.debug('User logged in successfully')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            logger.debug('Login failed - invalid credentials')
            flash('Invalid email or password', 'danger')
    
    logger.debug('Rendering login template')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    logger.debug('Logout route accessed')
    logout_user()
    return redirect(url_for('home'))

@app.route('/new_tweet', methods=['POST'])
@login_required
def new_tweet():
    form = TweetForm()
    if form.validate_on_submit():
        tweet = Tweet(content=form.content.data, author=current_user)
        
        # Handle image upload
        if 'image' in request.files:
            file = request.files['image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], 'post_images', filename))
                tweet.image = os.path.join('post_images', filename)
        
        # Extract and create hashtags
        tweet.extract_hashtags()
        
        db.session.add(tweet)
        db.session.commit()
        flash('Your tweet has been posted!', 'success')
    return redirect(url_for('home'))

@app.route('/upload_profile_pic', methods=['POST'])
@login_required
def upload_profile_pic():
    if 'file' not in request.files:
        flash('No file selected', 'error')
        return redirect(url_for('edit_profile'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('edit_profile'))
    
    if file and allowed_file(file.filename):
        try:
            # Generate secure filename with username and timestamp
            filename = secure_filename(file.filename)
            filename = f"{current_user.username}_{int(time.time())}_{filename}"
            
            # Ensure upload directory exists
            os.makedirs(UPLOAD_FOLDER, exist_ok=True)
            
            # Save the file
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            file.save(file_path)
            
            # Delete old profile picture if it exists and it's not the default
            if current_user.profile_pic and current_user.profile_pic != 'default.png':
                old_file = os.path.join(UPLOAD_FOLDER, current_user.profile_pic)
                if os.path.exists(old_file):
                    try:
                        os.remove(old_file)
                    except Exception as e:
                        app.logger.error(f"Error deleting old profile picture: {e}")
            
            # Update user's profile picture in database
            current_user.profile_pic = filename
            db.session.commit()
            
            flash('Profile picture updated successfully!', 'success')
        except Exception as e:
            app.logger.error(f"Error uploading profile picture: {e}")
            flash('An error occurred while uploading the profile picture', 'error')
            return redirect(url_for('edit_profile'))
            
        return redirect(url_for('edit_profile'))
    else:
        flash('Invalid file type. Please upload a PNG, JPG, JPEG, or GIF file.', 'error')
        return redirect(url_for('edit_profile'))

@app.route('/static/uploads/profile_pics/<path:filename>')
def serve_profile_pic(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

@app.route('/upload_cover_photo', methods=['POST'])
@login_required
def upload_cover_photo():
    if 'cover_photo' not in request.files:
        flash('No file selected', 'danger')
        return redirect(url_for('edit_profile'))
    
    file = request.files['cover_photo']
    if file.filename == '':
        flash('No file selected', 'danger')
        return redirect(url_for('edit_profile'))
        
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = f"cover_photos/{filename}"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], 'cover_photos', filename))
        
        current_user.cover_photo = filepath
        db.session.commit()
        flash('Cover photo updated successfully!', 'success')
    
    return redirect(url_for('edit_profile'))

@app.route('/hashtag/<tag>')
def hashtag(tag):
    hashtag = Hashtag.query.filter_by(name=tag.lower()).first_or_404()
    tweets = Tweet.query.filter(Tweet.hashtags.contains(hashtag)).order_by(Tweet.date_posted.desc()).all()
    trending_hashtags = Hashtag.query.join(Hashtag.posts).group_by(Hashtag.id).order_by(db.func.count().desc()).limit(5).all()
    return render_template('hashtag.html', hashtag=hashtag, tweets=tweets, trending_hashtags=trending_hashtags)

@app.route('/trending')
def trending():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    # Always try to fetch news
    if fetch_calvin_chimes_news():
        logger.info("News fetched successfully")
    else:
        logger.error("Failed to fetch news")
    
    # Get news items for the sidebar
    news_items = News.query.order_by(News.published_date.desc()).paginate(page=page, per_page=per_page)
    
    # Get messages for the main content
    if current_user.is_authenticated:
        messages = Message.query.join(
            ConversationParticipants, 
            Message.conversation_id == ConversationParticipants.conversation_id
        ).filter(
            ConversationParticipants.user_id == current_user.id
        ).order_by(Message.timestamp.desc()).limit(20).all()
    else:
        messages = []
    
    return render_template('trending.html', news_items=news_items, messages=messages)

@app.route('/tweet/<int:tweet_id>/like', methods=['POST'])
@login_required
def like_tweet(tweet_id):
    tweet = Tweet.query.get_or_404(tweet_id)
    like = Like.query.filter_by(user_id=current_user.id, tweet_id=tweet.id).first()
    
    try:
        if like:
            db.session.delete(like)
            db.session.commit()
            liked = False
        else:
            like = Like(user_id=current_user.id, tweet_id=tweet.id)
            db.session.add(like)
            db.session.commit()
            liked = True
            
        return jsonify({
            'success': True,
            'liked': liked,
            'likes_count': len(tweet.likes)
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@app.route('/tweet/<int:tweet_id>/retweet', methods=['POST'])
@login_required
def retweet(tweet_id):
    tweet = Tweet.query.get_or_404(tweet_id)
    retweet = Retweet.query.filter_by(user_id=current_user.id, tweet_id=tweet.id).first()
    
    try:
        if retweet:
            db.session.delete(retweet)
            db.session.commit()
            retweeted = False
        else:
            retweet = Retweet(user_id=current_user.id, tweet_id=tweet.id)
            db.session.add(retweet)
            db.session.commit()
            retweeted = True
            
        return jsonify({
            'success': True,
            'retweeted': retweeted,
            'retweets_count': len(tweet.retweets)
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@app.route('/user/<string:username>')
def user_profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    tweets = Tweet.query.filter_by(user_id=user.id).order_by(Tweet.date_posted.desc()).all()
    form = FollowForm()
    return render_template('profile.html', user=user, tweets=tweets, form=form)

@app.route('/follow/<string:username>', methods=['POST'])
@login_required
def follow(username):
    user = User.query.filter_by(username=username).first_or_404()
    if user == current_user:
        flash('You cannot follow yourself!', 'danger')
        return redirect(url_for('home'))
    
    if current_user.is_following(user):
        current_user.unfollow(user)
        flash(f'You have unfollowed {user.get_display_name()}!', 'success')
    else:
        current_user.follow(user)
        flash(f'You are now following {user.get_display_name()}!', 'success')
    
    return redirect(request.referrer or url_for('home'))

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        current_user.bio = request.form.get('bio', '')
        db.session.commit()
        flash('Your profile has been updated!', 'success')
        return redirect(url_for('user_profile', username=current_user.username))
    return render_template('edit_profile.html')

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

@app.route('/messages')
@app.route('/messages/<int:conversation_id>')
@login_required
def messages(conversation_id=None):
    form = MessageForm()  # Create form instance
    # Get all conversations for the current user
    user_conversations = ConversationParticipants.query.filter_by(user_id=current_user.id).all()
    conversations = [p.conversation for p in user_conversations]
    
    # Get the latest message for each conversation
    for conv in conversations:
        # Convert dynamic query to list to allow last message access
        conv.latest_message = conv.messages.order_by(Message.timestamp.desc()).first()
    
    # Sort conversations by latest message timestamp or creation date
    conversations.sort(
        key=lambda x: (x.latest_message.timestamp if x.latest_message else x.created_at),
        reverse=True
    )
    
    selected_conversation = None
    messages = []
    other_participant = None
    
    if conversation_id:
        selected_conversation = Conversation.query.get_or_404(conversation_id)
        # Check if user is part of this conversation
        if not any(p.user_id == current_user.id for p in selected_conversation.participants):
            flash('You do not have access to this conversation.', 'danger')
            return redirect(url_for('messages'))
        
        messages = selected_conversation.messages.order_by(Message.timestamp.asc()).all()
        # Get the other participant
        other_participant = next(
            (p.user for p in selected_conversation.participants if p.user_id != current_user.id),
            None
        )
        
        # Mark messages as read
        for message in messages:
            if message.sender_id != current_user.id and not message.is_read:
                message.is_read = True
        db.session.commit()
    
    return render_template(
        'messages.html',
        conversations=conversations,
        selected_conversation=selected_conversation,
        messages=messages,
        other_participant=other_participant,
        form=form  # Pass form to template
    )

@app.route('/messages/<int:conversation_id>/send', methods=['POST'])
@login_required
def send_message(conversation_id):
    content = request.form.get('content')
    if not content:
        flash('Message cannot be empty.', 'danger')
        return redirect(url_for('messages', conversation_id=conversation_id))
        
    conversation = Conversation.query.get_or_404(conversation_id)
    if not any(p.user_id == current_user.id for p in conversation.participants):
        abort(403)
    
    message = Message(
        conversation_id=conversation_id,
        sender_id=current_user.id,
        content=content
    )
    db.session.add(message)
    db.session.commit()
    
    return redirect(url_for('messages', conversation_id=conversation_id))

@app.route('/api/messages/<int:conversation_id>/updates')
@login_required
def message_updates(conversation_id):
    conversation = Conversation.query.get_or_404(conversation_id)
    if current_user not in conversation.participants:
        abort(403)
    
    # Get last read timestamp for current user
    participant = ConversationParticipants.query.filter_by(
        conversation_id=conversation_id,
        user_id=current_user.id
    ).first()
    
    # Get new messages since last read
    new_messages = Message.query.filter(
        Message.conversation_id == conversation_id,
        Message.timestamp > participant.last_read
    ).all()
    
    # Update last read timestamp
    participant.last_read = datetime.utcnow()
    db.session.commit()
    
    return jsonify({
        'messages': [{
            'id': msg.id,
            'content': msg.content,
            'sender_id': msg.sender_id,
            'timestamp': msg.timestamp.strftime('%I:%M %p'),
            'is_read': msg.is_read
        } for msg in new_messages]
    })

@app.route('/get_messages/<int:conversation_id>')
@login_required
def get_messages(conversation_id):
    conversation = Conversation.query.get_or_404(conversation_id)
    
    # Check if user is a participant
    if current_user not in conversation.participants:
        return jsonify({'error': 'Unauthorized'}), 403
    
    messages_data = []
    for message in conversation.messages:
        messages_data.append({
            'content': message.content,
            'sender_id': message.sender_id,
            'timestamp': message.timestamp.strftime('%H:%M'),
            'is_read': message.is_read
        })
    
    return jsonify({'messages': messages_data})

@app.route('/new_conversation', methods=['POST'])
@login_required
def new_conversation():
    try:
        data = request.get_json()
        if not data:
            app.logger.error('No JSON data received')
            return jsonify({'error': 'No data received'}), 400

        recipient_id = data.get('recipient_id')
        message_content = data.get('message')

        app.logger.info(f'Received request: recipient_id={recipient_id}, message={message_content}')

        if not recipient_id or not message_content:
            app.logger.error('Missing recipient or message')
            return jsonify({'error': 'Missing recipient or message'}), 400

        try:
            recipient_id = int(recipient_id)
        except ValueError:
            app.logger.error(f'Invalid recipient_id format: {recipient_id}')
            return jsonify({'error': 'Invalid recipient ID'}), 400

        # Check if recipient exists
        recipient = User.query.get(recipient_id)
        if not recipient:
            app.logger.error(f'Recipient not found: {recipient_id}')
            return jsonify({'error': 'Recipient not found'}), 404

        # Check if user follows the recipient
        if not current_user.is_following(recipient):
            app.logger.error(f'User {current_user.id} does not follow recipient {recipient_id}')
            return jsonify({'error': 'You can only send messages to users you follow'}), 403

        # Check if conversation exists
        existing_participants = ConversationParticipants.query.filter_by(user_id=current_user.id).all()
        conversation = None
        
        for participant in existing_participants:
            conv = participant.conversation
            other_participant = ConversationParticipants.query.filter_by(
                conversation_id=conv.id,
                user_id=recipient_id
            ).first()
            
            if other_participant:
                conversation = conv
                break

        if not conversation:
            app.logger.info('Creating new conversation')
            # Create new conversation
            conversation = Conversation()
            db.session.add(conversation)
            db.session.flush()  # Get the conversation ID

            # Add participants
            participant1 = ConversationParticipants(conversation_id=conversation.id, user_id=current_user.id)
            participant2 = ConversationParticipants(conversation_id=conversation.id, user_id=recipient_id)
            db.session.add_all([participant1, participant2])
            db.session.flush()
        else:
            app.logger.info(f'Using existing conversation: {conversation.id}')

        # Create and save the message
        message = Message(
            conversation_id=conversation.id,
            sender_id=current_user.id,
            content=message_content
        )
        db.session.add(message)
        db.session.commit()

        app.logger.info(f'Message sent successfully in conversation {conversation.id}')
        return jsonify({
            'success': True,
            'conversation_id': conversation.id,
            'message': 'Message sent successfully'
        }), 200

    except Exception as e:
        app.logger.error(f'Error in new_conversation: {str(e)}')
        db.session.rollback()
        return jsonify({'error': 'An error occurred while sending the message'}), 500

@app.route('/news')
def news():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    news_items = News.query.order_by(News.published_date.desc()).paginate(page=page, per_page=per_page)
    return render_template('news.html', news_items=news_items)

@app.route('/news/<int:news_id>')
def news_detail(news_id):
    news_item = News.query.get_or_404(news_id)
    form = NewsCommentForm()
    return render_template('news_detail.html', news=news_item, form=form)

@app.route('/news/<int:news_id>/comment', methods=['POST'])
@login_required
def add_news_comment(news_id):
    news_item = News.query.get_or_404(news_id)
    form = NewsCommentForm()
    if form.validate_on_submit():
        comment = NewsComment(
            content=form.content.data,
            news_id=news_id,
            user_id=current_user.id
        )
        db.session.add(comment)
        db.session.commit()
        flash('Your comment has been posted!', 'success')
    return redirect(url_for('news_detail', news_id=news_id))

def fetch_calvin_chimes_news():
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get('https://calvinchimes.org', headers=headers, timeout=10)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        articles = soup.find_all('article', class_='post')
        
        for article in articles[:10]:  # Get top 10 articles
            # Get the title and link
            title_elem = article.find('h2', class_='entry-title')
            if not title_elem or not title_elem.find('a'):
                continue
                
            title = title_elem.find('a').text.strip()
            url = title_elem.find('a')['href']
            
            # Check if article already exists
            if News.query.filter_by(url=url).first():
                continue
            
            # Get the summary
            summary_elem = article.find('div', class_='entry-content')
            summary = summary_elem.text.strip() if summary_elem else ''
            
            # Get the image
            image_elem = article.find('img')
            image_url = image_elem['src'] if image_elem and 'src' in image_elem.attrs else None
            
            # Get the date
            date_elem = article.find('time', class_='entry-date')
            if date_elem and 'datetime' in date_elem.attrs:
                published_date = datetime.strptime(date_elem['datetime'][:19], '%Y-%m-%dT%H:%M:%S')
            else:
                published_date = datetime.utcnow()
            
            # Create new news article
            news = News(
                title=title,
                url=url,
                summary=summary[:500] + '...' if len(summary) > 500 else summary,
                image_url=image_url,
                published_date=published_date
            )
            db.session.add(news)
        
        db.session.commit()
        logger.info(f"Successfully fetched {len(articles)} articles from Calvin Chimes")
        return True
    except Exception as e:
        logger.error(f"Error fetching news: {str(e)}")
        db.session.rollback()
        return False

@login_manager.user_loader
def load_user(user_id):
    logger.debug('Loading user with id: %s', user_id)
    return User.query.get(int(user_id))

@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=8080)
