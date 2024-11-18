from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import validates
from sqlalchemy_serializer import SerializerMixin
from datetime import datetime

db = SQLAlchemy()

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(), nullable=False)
    phone_number = db.Column(db.String(), nullable=False)
    email = db.Column(db.String(), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    type = db.Column(db.String(), nullable=False)
    
    @validates('password')
    def validate_password(self, key, password):
        if len(password) < 8:
            raise ValueError('Password must be more than 8 characters.')
        return password
    
    @validates('email')
    def validate_email(self, key, email):
        allowed_domains = ["@gmail.com", "@outlook.com", "@yahoo.com"]
        if not any(email.endswith(domain) for domain in allowed_domains):
            raise ValueError("Email must end with @gmail.com, @outlook.com, or @yahoo.com.")
        return email

    def __repr__(self):
        return f'<User {self.name}>'

    # Define relationship with Disaster using foreign key
    reports = db.relationship(
        'Disaster',
        backref='reporter',
        lazy=True,
        cascade="all, delete-orphan"
    )
    
    # serialize_rules = ('-reports.reporter',)  
    
    def __repr__(self):
        return f'<User {self.name}>'


class Rescuer(db.Model, SerializerMixin):
    __tablename__ = 'rescuers'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(), nullable=False)
    phone_number = db.Column(db.String(), nullable=False)
    email = db.Column(db.String(), unique=True, nullable=False)
    role = db.Column(db.String(), nullable=False)  # e.g., firefighter, etc.

    # Define relationship with Disaster using foreign key
    assigned_disasters = db.relationship(
        'Disaster',
        backref='rescuer',
        lazy=True,
        cascade="all, delete-orphan"
    )
    
    # serialize_rules = ('-disasters.assigned_rescuer',)  

    def __repr__(self):
        return f'<Rescuer {self.name}>'


class Disaster(db.Model, SerializerMixin):
    __tablename__ = 'disasters'
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(), nullable=False)  
    date_reported = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  
    rescuer_id = db.Column(db.Integer, db.ForeignKey('rescuers.id'), nullable=False)  
    
    # reporter = db.relationship('User', backref='User.reports', lazy=True)
    
    # Relationships for serialization rules
    # serialize_rules = ('-reporter.reports', '-assigned_rescuer.disasters')

    def __repr__(self):
        return f'<Disaster {self.description} - Reported by {self.reporter.name}>'



