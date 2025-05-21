from app import db
from flask_login import UserMixin
from datetime import datetime

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    analyses = db.relationship('Analysis', backref='user', lazy=True)
    
    def __repr__(self):
        return f'<User {self.username}>'

class Analysis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email_content = db.Column(db.Text)  # Store first part of the email
    prediction = db.Column(db.Integer)  # 0 for legitimate, 1 for phishing
    confidence = db.Column(db.Float)
    features = db.Column(db.Text)  # JSON string of important features
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    
    def __repr__(self):
        return f'<Analysis {self.id} - {"Phishing" if self.prediction == 1 else "Legitimate"}>'
