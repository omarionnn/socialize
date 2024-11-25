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
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email

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
csrf = CSRFProtect(app)  # Initialize CSRF protection
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# File upload configuration
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static/uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
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
    profile_pic = db.Column(db.String(120), nullable=False, default='profile_pics/default.jpg')
    bio = db.Column(db.String(500))
    cover_photo = db.Column(db.String(100), default='default_cover.jpg')
    is_verified = db.Column(db.Boolean, default=False)
    tweets = db.relationship('Tweet', backref='author', lazy=True)
    likes = db.relationship('Like', backref='user', lazy=True)
    retweets = db.relationship('Retweet', backref='user', lazy=True)
    following = db.relationship('Follow',
                            foreign_keys='Follow.follower_id',
                            backref=db.backref('follower', lazy='joined'),
                            lazy='dynamic',
                            cascade='all, delete-orphan')
    followers = db.relationship('Follow',
                            foreign_keys='Follow.followed_id',
                            backref=db.backref('followed', lazy='joined'),
                            lazy='dynamic',
                            cascade='all, delete-orphan')
    messages_sent = db.relationship('Message',
                                foreign_keys='Message.sender_id',
                                backref=db.backref('sender', lazy=True),
                                lazy='dynamic')
    conversations = db.relationship('ConversationParticipants',
                                backref=db.backref('user', lazy=True),
                                lazy='dynamic')

    def is_following(self, user):
        if user is None:
            return False
        return Follow.query.filter_by(
            follower_id=self.id,
            followed_id=user.id
        ).first() is not None

    def follow(self, user):
        if not self.is_following(user):
            f = Follow(follower_id=self.id, followed_id=user.id)
            db.session.add(f)

    def unfollow(self, user):
        f = Follow.query.filter_by(
            follower_id=self.id,
            followed_id=user.id
        ).first()
        if f:
            db.session.delete(f)

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

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@login_manager.user_loader
def load_user(user_id):
    logger.debug('Loading user with id: %s', user_id)
    return User.query.get(int(user_id))

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

# Routes
@app.route('/')
@app.route('/home')
def home():
    logger.debug('Home route accessed')
    if current_user.is_authenticated:
        logger.debug('User is authenticated, retrieving followed users')
        tweets = Tweet.query.order_by(Tweet.date_posted.desc()).all()
    else:
        logger.debug('User is not authenticated, retrieving all tweets')
        tweets = Tweet.query.order_by(Tweet.date_posted.desc()).all()

    form = TweetForm()
    all_users = User.query.all()
    return render_template('home.html', tweets=tweets, all_users=all_users, form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    logger.debug('Register route accessed')
    if current_user.is_authenticated:
        logger.debug('User already authenticated, redirecting to home')
        return redirect(url_for('home'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        logger.debug('Processing POST request')
        
        # Check if username already exists
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash('That username is already taken. Please choose a different one.', 'danger')
            return render_template('register.html', form=form)
        
        # Check if email already exists
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('That email is already registered. Please use a different one.', 'danger')
            return render_template('register.html', form=form)
        
        try:
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user = User(username=form.username.data,
                       email=form.email.data,
                       password=hashed_password)
            db.session.add(user)
            db.session.commit()
            logger.debug('User registered successfully')
            flash('Account created successfully! You can now log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            logger.error(f'Error during registration: {str(e)}')
            flash('An error occurred during registration. Please try again.', 'danger')
            return render_template('register.html', form=form)
    
    logger.debug('Rendering register template')
    return render_template('register.html', form=form)

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
    if 'profile_pic' not in request.files:
        flash('No file selected', 'danger')
        return redirect(url_for('user_profile', username=current_user.username))
    
    file = request.files['profile_pic']
    if file.filename == '':
        flash('No file selected', 'danger')
        return redirect(url_for('user_profile', username=current_user.username))
    
    if file and allowed_file(file.filename):
        try:
            # Create a secure filename with timestamp
            filename = secure_filename(file.filename)
            timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
            filename = f"profile_pics/{timestamp}_{filename}"
            
            # Save the file
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            # Delete old profile picture if it exists and it's not the default
            if current_user.profile_pic != 'profile_pics/default.jpg':
                old_file = os.path.join(app.config['UPLOAD_FOLDER'], current_user.profile_pic)
                if os.path.exists(old_file):
                    os.remove(old_file)
            
            # Update user's profile picture in database
            current_user.profile_pic = filename
            db.session.commit()
            
            flash('Profile picture updated successfully!', 'success')
        except Exception as e:
            app.logger.error(f"Error uploading profile picture: {str(e)}")
            flash('An error occurred while uploading the profile picture', 'danger')
            
    else:
        flash('Invalid file type. Please use jpg, jpeg, png, or gif files.', 'danger')
    
    return redirect(url_for('user_profile', username=current_user.username))

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
    user = User.query.filter_by(username=username).first_or_404()
    tweets = Tweet.query.filter_by(user_id=user.id).order_by(Tweet.date_posted.desc()).all()
    form = FollowForm()
    return render_template('profile.html', user=user, tweets=tweets, form=form)

@app.route('/follow/<string:username>', methods=['POST'])
@login_required
def follow(username):
    form = FollowForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=username).first_or_404()
        
        if user == current_user:
            flash('You cannot follow yourself!', 'danger')
            return redirect(url_for('user_profile', username=username))
        
        if current_user.is_following(user):
            current_user.unfollow(user)
            db.session.commit()
            flash(f'You have unfollowed {username}!', 'success')
        else:
            current_user.follow(user)
            db.session.commit()
            flash(f'You are now following {username}!', 'success')
    else:
        flash('Form validation failed. Please try again.', 'danger')
        app.logger.error(f'Form errors: {form.errors}')
    
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

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

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

@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=8080)
