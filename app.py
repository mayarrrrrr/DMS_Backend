from flask import Flask, request, jsonify, make_response,redirect,url_for
from flask_migrate import Migrate
from flask_restful import Resource, Api, reqparse
from models import db, User,Disaster,Rescuer
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, create_access_token,unset_jwt_cookies
from flask_cors import CORS, cross_origin
from flask_bcrypt import Bcrypt
from authlib.integrations.flask_client import OAuth



app = Flask(__name__)

CORS(app,resources={r"/*": {"origins": ["http://localhost:5173","http://localhost:5174"],"supports_credentials": True,"methods": ["GET", "POST","PATCH", "PUT", "DELETE", "OPTIONS"]}})

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.json.compact = False

app.secret_key = 'secret key'
app.config['JWT_SECRET_KEY'] = "b'\x03\xa3\x8c\xb3\n\xf4}\x16aFh\xc5'"

db.init_app(app)

migrate = Migrate(app, db)
api = Api(app)
jwt = JWTManager(app)
bcrypt = Bcrypt(app)

# Initialize OAuth
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id='YOUR_GOOGLE_CLIENT_ID',
    client_secret='YOUR_GOOGLE_CLIENT_SECRET',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    access_token_params=None,
    client_kwargs={'scope': 'openid profile email'},
)


class UserRegister(Resource):
    @cross_origin()
    def post(self):
        name = request.json['name']
        phone_number = request.json['phone_number']
        email = request.json['email']
        
        password = str(request.json['password'])
        type = request.json['type']

        #print(f"Type of password: {type(password)}") 

        user_exists = User.query.filter_by(email=email).first()

        if user_exists:
            return jsonify({'error': 'User already exists'}), 409
        # if email exists, or passwords dont match, do something 
        #if password != confirm_password:
        #    return jsonify({'Error': 'Passwords not matching'})

        hashed_pw = bcrypt.generate_password_hash(password)
       # hashed_cpw = bcrypt.generate_password_hash(confirm_password)

        access_token = create_access_token(identity=email)

        new_user = User(
            name = name,
            phone_number = phone_number,
            email=email, 
             
            password=hashed_pw,
            type=type
        )
        db.session.add(new_user)
        db.session.commit()

        return jsonify({
            "id": new_user.id,
            "email": new_user.email,
            "name": new_user.name,
            "type": new_user.type,
            "access_token": access_token,
        }),201


# class UserLogin(Resource):
#     @cross_origin()
#     def post(self):
#         email = request.json['email']
#         password = request.json['password']

#         user = User.query.filter_by(email=email).first()

#         if user is None:
#             return jsonify({'error': 'Unauthorized'}), 401

#         if not bcrypt.check_password_hash(user.password, password):
#             return jsonify({'error': 'Unauthorized, incorrect password'}), 401
        
#         access_token = create_access_token(identity=email)
#         user.access_token = access_token


#         return jsonify({
#             "id": user.id,
#             "email": user.email,
#             "access_token": user.access_token,
#             "type":user.type
          
#         })

class UserLogin(Resource):
    @cross_origin()
    def post(self):
        """
        Unified login for manual and OAuth.
        Determines the login type based on request content.
        """
        email = request.json.get('email')
        password = request.json.get('password')

        if email and password:
            # Manual login flow
            user = User.query.filter_by(email=email).first()
            if not user or not bcrypt.check_password_hash(user.password, password):
                return jsonify({'error': 'Unauthorized'}), 401

            # Generate JWT token
            access_token = create_access_token(identity=email)
            return jsonify({
                "id": user.id,
                "email": user.email,
                "access_token": access_token,
                "type": user.type,
            })

        # If no email and password, assume OAuth flow
        redirect_uri = url_for('google_callback', _external=True)
        return redirect(google.authorize_redirect(redirect_uri))


# Google OAuth Callback
class GoogleCallback(Resource):
    def get(self):
        """
        Handles the OAuth callback from Google.
        """
        token = google.authorize_access_token()
        user_info = google.get('userinfo').json()

        # Extract user details
        email = user_info.get('email')
        name = user_info.get('name', 'Unknown')

        # Check if user exists, else create a new one
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(email=email, name=name, type="oauth")
            db.session.add(user)
            db.session.commit()

        # Generate JWT token
        access_token = create_access_token(identity=email)
        return jsonify({
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "access_token": access_token,
            "type": user.type,
        })






        
class Disasters(Resource):
    def get(self):
       
            disasters = [disasters.to_dict(only=('id',  'description', 'date_reported','reporter.id', 'reporter.name','reporter.email')) for disasters in Disaster.query.all()]
            return make_response(jsonify(disasters),200)
        
    def post(self):  
        data = request.json

        new_disaster = Disaster(
            description = data["description"],
            
            user_id = data["user_id"],
            rescuer_id = data['rescuer_id']
            
        )

        db.session.add(new_disaster)
        db.session.commit()

        return make_response(jsonify(new_disaster.to_dict(only=("description","date_reported","user_id","rescuer_id"))),200) 
    
class DisasterByID(Resource):
    def get(self):
        disasters = [disasters.to_dict(only=('id',  'description', 'date_reported')) for disasters in Disaster.query.filter(Disaster.id == id)]
        return make_response(jsonify(disasters),200)
    
    def patch(self,id):

        data = request.get_json()

        disaster = Disaster.query.filter(Disaster.id == id).first()

        for attr in data:

            setattr(disaster,attr,data.get(attr))   

        db.session.add(disaster)
        db.session.commit()

        return make_response(disaster.to_dict(only=('id',  'description', 'date_reported')),200)

    def delete(self,id):

        disaster = Disaster.query.filter(Disaster.id == id).first()

        if disaster:
            db.session.delete(disaster)
            db.session.commit()
            return make_response("",204)
        
        else:
            return make_response(jsonify({"error":"disaster not found"}),404)
        
class Rescuers(Resource):
    def get(self):
        rescuers = [rescuers.to_dict(only=('id',  'name', 'phone_number','email','role')) for rescuers in Rescuer.query.all()]
        return make_response(jsonify(rescuers),200)
    
    def post(self):  
        data = request.json

        new_rescuer = Rescuer(
            name = data["name"],
            phone_number = data["phone_number"],
            email = data['email'],
            role = data['role']
            
        )

        db.session.add(new_rescuer)
        db.session.commit()

        return make_response(jsonify(new_rescuer.to_dict(only=("name","phone_number","email","role"))),200) 
    
class RescuerByID(Resource):
    def get(self,id):
        rescuer = [rescuer.to_dict(only=("id","name","phone_number","email","role")) for rescuer in Rescuer.query.filter(Rescuer.id == id)]
        return make_response(jsonify(rescuer),200)
    
    def patch(self,id):

        data = request.get_json()

        rescuer = Rescuer.query.filter(Rescuer.id == id).first()

        for attr in data:

            setattr(rescuer,attr,data.get(attr))   

        db.session.add(rescuer)
        db.session.commit()

        return make_response(rescuer.to_dict(only=("id","name","phone_number","email","role")),200)

    def delete(self,id):

        rescuer = Rescuer.query.filter(Rescuer.id == id).first()

        if rescuer:
            db.session.delete(rescuer)
            db.session.commit()
            return make_response("",204)
        
        else:
            return make_response(jsonify({"error":"rescuer not found"}),404)    
               
        
        
              
# Register API resources
api.add_resource(UserLogin, '/login')
api.add_resource(GoogleCallback, '/login/callback')    
api.add_resource(UserRegister,"/signup")
api.add_resource(Disasters,"/disasters")
api.add_resource(DisasterByID,"/disaster/<int:id>")
api.add_resource(Rescuers,"/rescuers")
api.add_resource(RescuerByID,"/rescuer/<int:id>")


if __name__ == '__main__':
    app.run(port=5555, debug=True)