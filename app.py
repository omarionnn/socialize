from flask import Flask, render_template, url_for, flash, redirect, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
import os
import logging
from werkzeug.utils import secure_filename
import re

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
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# File upload configuration
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static/uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create upload folders if they don't exist
os.makedirs(os.path.join(UPLOAD_FOLDER, 'profile_pics'), exist_ok=True)
os.makedirs(os.path.join(UPLOAD_FOLDER, 'cover_photos'), exist_ok=True)
os.makedirs(os.path.join(UPLOAD_FOLDER, 'post_images'), exist_ok=True)

# Database Models
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

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    bio = db.Column(db.String(500))
    profile_pic = db.Column(db.String(100), default='default.jpg')
    cover_photo = db.Column(db.String(100), default='default_cover.jpg')
    is_verified = db.Column(db.Boolean, default=False)
    tweets = db.relationship('Tweet', backref='author', lazy=True)
    following = db.relationship('Follow',
                              foreign_keys='Follow.follower_id',
                              backref=db.backref('follower', lazy='joined'),
                              lazy='dynamic')
    followers = db.relationship('Follow',
                              foreign_keys='Follow.followed_id',
                              backref=db.backref('followed', lazy='joined'),
                              lazy='dynamic')
    user_conversations = db.relationship('ConversationParticipants', backref='user', lazy=True)

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

class Conversation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    messages = db.relationship('Message', backref='conversation', lazy=True, order_by='Message.timestamp')
    participants = db.relationship('User', 
                                 secondary='conversation_participants',
                                 backref=db.backref('conversations', lazy=True),
                                 lazy='joined')

class ConversationParticipants(db.Model):
    __tablename__ = 'conversation_participants'
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversation.id'), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    last_read = db.Column(db.DateTime, default=datetime.utcnow)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversation.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    
    sender = db.relationship('User', backref='sent_messages')

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@login_manager.user_loader
def load_user(user_id):
    logger.debug('Loading user with id: %s', user_id)
    return User.query.get(int(user_id))

# Routes
@app.route('/')
@app.route('/home')
def home():
    logger.debug('Home route accessed')
    if current_user.is_authenticated:
        logger.debug('User is authenticated, retrieving followed users')
        followed_users = [follow.followed_id for follow in current_user.following.all()]
        followed_users.append(current_user.id)
        tweets = Tweet.query.filter(Tweet.user_id.in_(followed_users)).order_by(Tweet.date_posted.desc()).all()
    else:
        logger.debug('User is not authenticated, retrieving all tweets')
        tweets = Tweet.query.order_by(Tweet.date_posted.desc()).all()
    
    # Get all users for the discover section
    all_users = User.query.all()
    return render_template('home.html', tweets=tweets, all_users=all_users)

@app.route('/register', methods=['GET', 'POST'])
def register():
    logger.debug('Register route accessed')
    if current_user.is_authenticated:
        logger.debug('User already authenticated, redirecting to home')
        return redirect(url_for('home'))
    if request.method == 'POST':
        logger.debug('Processing POST request')
        hashed_password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        user = User(username=request.form['username'],
                   email=request.form['email'],
                   password=hashed_password)
        db.session.add(user)
        db.session.commit()
        logger.debug('User registered successfully')
        flash('Account created successfully!', 'success')
        return redirect(url_for('login'))
    logger.debug('Rendering register template')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    logger.debug('Login route accessed')
    if current_user.is_authenticated:
        logger.debug('User already authenticated, redirecting to home')
        return redirect(url_for('home'))
    if request.method == 'POST':
        logger.debug('Processing POST request')
        user = User.query.filter_by(email=request.form['email']).first()
        if user and bcrypt.check_password_hash(user.password, request.form['password']):
            logger.debug('User authenticated successfully')
            login_user(user)
            return redirect(url_for('home'))
        else:
            logger.debug('User authentication failed')
            flash('Login unsuccessful. Please check email and password.', 'danger')
    logger.debug('Rendering login template')
    return render_template('login.html')

@app.route('/logout')
def logout():
    logger.debug('Logout route accessed')
    logout_user()
    return redirect(url_for('home'))

@app.route('/new_tweet', methods=['POST'])
@login_required
def new_tweet():
    content = request.form.get('content')
    if not content:
        flash('Tweet cannot be empty!', 'danger')
        return redirect(url_for('home'))
        
    # Handle image upload
    image_filename = None
    if 'image' in request.files:
        file = request.files['image']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            image_filename = f"post_images/{filename}"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], 'post_images', filename))

    tweet = Tweet(content=content, author=current_user, image=image_filename)
    
    # Extract and save hashtags
    hashtags = tweet.extract_hashtags()
    for tag_name in hashtags:
        tag = Hashtag.query.filter_by(name=tag_name.lower()).first()
        if not tag:
            tag = Hashtag(name=tag_name.lower())
            db.session.add(tag)
        tweet.hashtags.append(tag)
    
    db.session.add(tweet)
    db.session.commit()
    return redirect(url_for('home'))

@app.route('/upload_profile_pic', methods=['POST'])
@login_required
def upload_profile_pic():
    if 'profile_pic' not in request.files:
        flash('No file selected', 'danger')
        return redirect(url_for('edit_profile'))
    
    file = request.files['profile_pic']
    if file.filename == '':
        flash('No file selected', 'danger')
        return redirect(url_for('edit_profile'))
        
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = f"profile_pics/{filename}"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], 'profile_pics', filename))
        
        current_user.profile_pic = filepath
        db.session.commit()
        flash('Profile picture updated successfully!', 'success')
    
    return redirect(url_for('edit_profile'))

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
    # Get trending hashtags from the last 7 days
    week_ago = datetime.utcnow() - timedelta(days=7)
    trending_hashtags = db.session.query(
        Hashtag,
        db.func.count(tweet_hashtags.c.tweet_id).label('count')
    ).join(tweet_hashtags).join(Tweet).filter(
        Tweet.date_posted >= week_ago
    ).group_by(Hashtag.id).order_by(
        db.text('count DESC')
    ).limit(10).all()
    
    return render_template('trending.html', trending_hashtags=trending_hashtags)

@app.route('/tweet/<int:tweet_id>/like', methods=['POST'])
@login_required
def like_tweet(tweet_id):
    logger.debug('Like tweet route accessed')
    tweet = Tweet.query.get_or_404(tweet_id)
    like = Like.query.filter_by(user_id=current_user.id, tweet_id=tweet.id).first()
    if like:
        logger.debug('Tweet already liked, removing like')
        db.session.delete(like)
    else:
        logger.debug('Tweet not liked, adding like')
        like = Like(user_id=current_user.id, tweet_id=tweet.id)
        db.session.add(like)
    db.session.commit()
    logger.debug('Like updated successfully')
    return jsonify({'likes': len(tweet.likes)})

@app.route('/tweet/<int:tweet_id>/retweet', methods=['POST'])
@login_required
def retweet(tweet_id):
    logger.debug('Retweet route accessed')
    tweet = Tweet.query.get_or_404(tweet_id)
    retweet = Retweet.query.filter_by(user_id=current_user.id, tweet_id=tweet.id).first()
    if retweet:
        logger.debug('Tweet already retweeted, removing retweet')
        db.session.delete(retweet)
    else:
        logger.debug('Tweet not retweeted, adding retweet')
        retweet = Retweet(user_id=current_user.id, tweet_id=tweet.id)
        db.session.add(retweet)
    db.session.commit()
    logger.debug('Retweet updated successfully')
    return jsonify({'retweets': len(tweet.retweets)})

@app.route('/user/<string:username>')
def user_profile(username):
    logger.debug('User profile route accessed')
    user = User.query.filter_by(username=username).first_or_404()
    tweets = Tweet.query.filter_by(author=user).order_by(Tweet.date_posted.desc()).all()
    return render_template('profile.html', user=user, tweets=tweets)

@app.route('/follow/<string:username>', methods=['POST'])
@login_required
def follow(username):
    logger.debug('Follow route accessed')
    user = User.query.filter_by(username=username).first()
    if user is None:
        logger.debug('User not found')
        flash(f'User {username} not found.', 'error')
        return redirect(url_for('home'))
    if user == current_user:
        logger.debug('User cannot follow themselves')
        flash('You cannot follow yourself!', 'error')
        return redirect(url_for('user_profile', username=username))
    logger.debug('User followed successfully')
    current_user.following.append(Follow(followed=user))
    db.session.commit()
    flash(f'You are now following {username}!', 'success')
    return redirect(url_for('user_profile', username=username))

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        current_user.bio = request.form.get('bio', '')
        db.session.commit()
        flash('Your profile has been updated!', 'success')
        return redirect(url_for('user_profile', username=current_user.username))
    return render_template('edit_profile.html')

@app.route('/uploaded_file/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/messages')
@app.route('/messages/<int:conversation_id>')
@login_required
def messages(conversation_id=None):
    conversations = current_user.conversations
    current_conversation = None
    if conversation_id:
        current_conversation = Conversation.query.get_or_404(conversation_id)
        # Mark messages as read
        unread_messages = Message.query.filter_by(
            conversation_id=conversation_id,
            is_read=False
        ).filter(Message.sender_id != current_user.id).all()
        for message in unread_messages:
            message.is_read = True
        db.session.commit()
    users = User.query.filter(User.id != current_user.id).all()
    return render_template('messages.html', 
                         conversations=conversations,
                         current_conversation=current_conversation,
                         users=users)

@app.route('/messages/new', methods=['POST'])
@login_required
def new_conversation():
    recipient_id = request.form.get('recipient')
    message_content = request.form.get('message')
    
    if not recipient_id or not message_content:
        flash('Please provide both recipient and message.', 'danger')
        return redirect(url_for('messages'))
    
    # Check if conversation already exists
    existing_conversations = current_user.conversations
    for conv in existing_conversations:
        if len(conv.participants) == 2:
            other_user = [p for p in conv.participants if p.id != current_user.id][0]
            if other_user.id == int(recipient_id):
                # Add message to existing conversation
                message = Message(
                    conversation_id=conv.id,
                    sender_id=current_user.id,
                    content=message_content
                )
                db.session.add(message)
                db.session.commit()
                return redirect(url_for('messages', conversation_id=conv.id))
    
    # Create new conversation
    conversation = Conversation()
    conversation.participants.append(current_user)
    conversation.participants.append(User.query.get(recipient_id))
    db.session.add(conversation)
    db.session.flush()
    
    # Add first message
    message = Message(
        conversation_id=conversation.id,
        sender_id=current_user.id,
        content=message_content
    )
    db.session.add(message)
    db.session.commit()
    
    return redirect(url_for('messages', conversation_id=conversation.id))

@app.route('/messages/<int:conversation_id>/send', methods=['POST'])
@login_required
def send_message(conversation_id):
    conversation = Conversation.query.get_or_404(conversation_id)
    if current_user not in conversation.participants:
        abort(403)
    
    content = request.form.get('content')
    if not content:
        flash('Message cannot be empty.', 'danger')
        return redirect(url_for('messages', conversation_id=conversation_id))
    
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

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=8000)