from flask import Flask, render_template, url_for, flash, redirect, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from datetime import datetime
import os
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///twitter.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    tweets = db.relationship('Tweet', backref='author', lazy=True)
    following = db.relationship('Follow',
                              foreign_keys='Follow.follower_id',
                              backref=db.backref('follower', lazy='joined'),
                              lazy='dynamic')
    followers = db.relationship('Follow',
                              foreign_keys='Follow.followed_id',
                              backref=db.backref('followed', lazy='joined'),
                              lazy='dynamic')

class Tweet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(280), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    likes = db.relationship('Like', backref='tweet', lazy=True)
    retweets = db.relationship('Retweet', backref='tweet', lazy=True)

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

@app.route('/tweet/new', methods=['POST'])
@login_required
def new_tweet():
    logger.debug('New tweet route accessed')
    content = request.form.get('content')
    if content:
        logger.debug('Processing new tweet')
        tweet = Tweet(content=content, author=current_user)
        db.session.add(tweet)
        db.session.commit()
        logger.debug('Tweet posted successfully')
        flash('Your tweet has been posted!', 'success')
    return redirect(url_for('home'))

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

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=8000)
