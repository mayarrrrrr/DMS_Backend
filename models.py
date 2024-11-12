from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import validates
from sqlalchemy_serializer import SerializerMixin
from datetime import datetime

db = SQLAlchemy()

class User(db.Model, SerializerMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(), nullable=False)
    phone_number = db.Column(db.String(), nullable=False)
    email = db.Column(db.String(), unique=True, nullable=False)
    type = db.Column(db.String(), nullable=False)
    
    @validates('password')
    def validate_password(self, key, password):
        if len(password) < 8:
            raise ValueError('Password must be more than 8 characters.')
        return password
    
    @validates('email')
    def validate_email(self, key, email):
        if not email.endswith("@gmail.com"):
            raise ValueError("Email is not valid. It should end with @gmail.com")
        return email

    reports = db.relationship('Disaster', backref='user', lazy=True)  
    
    
    serialize_rules = ('-reports.user',)  
    
    def __repr__(self):
        return f'<User {self.name}>'

class Rescuer(db.Model, SerializerMixin):
    __tablename__ = 'rescuer'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(), nullable=False)
    phone_number = db.Column(db.String(), nullable=False)
    email = db.Column(db.String(), unique=True, nullable=False)
    role = db.Column(db.String(), nullable=False)  # firefighter, etc.
    disasters = db.relationship('Disaster', backref='rescuer', lazy=True)  

    
    serialize_rules = ('-disasters.rescuer',)  

    def __repr__(self):
        return f'<Rescuer {self.name}>'



class Disaster(db.Model, SerializerMixin):
    __tablename__ = 'disaster'
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(), nullable=False)  
    date_reported = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  
    rescuer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  
    
    user = db.relationship('User', foreign_keys=[user_id], backref='reported_disasters')
    rescuer = db.relationship('User', foreign_keys=[rescuer_id], backref='responded_disasters')

    
    serialize_rules = ('-user.reported_disasters', '-rescuer.responded_disasters')

    def __repr__(self):
        return f'<Disaster {self.description} - Reported by {self.user.name}>'
    


class Reporter(db.Model, SerializerMixin):
    __tablename__ = 'reporter'
    id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    
    
    serialize_rules = ('-reports.user',)  
    
    def __repr__(self):
        return f'<Reporter {self.id} - {self.name}>'

