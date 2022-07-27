from datetime import datetime, timedelta
from flask_lambda import FlaskLambda
from functools import wraps
from flask import redirect, url_for, session, jsonify
from authlib.integrations.flask_client import OAuth
import boto3
from boto3.dynamodb.conditions import Key, Attr
import jwt
import secrets

app = FlaskLambda(__name__)

app.config['SECRET_KEY'] = secrets.SECRET_KEY
app.config['SESSION_COOKIE_NAME'] = 'google-login-session'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=secrets.TTL)

ddb = boto3.resource('dynamodb')
table = ddb.Table('UsersTable')
# oAuth Setup
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=secrets.client_id
    client_secret=secrets.client_secret
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',
    client_kwargs={'scope': 'openid email profile'},
)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = dict(session).get('profile', None)
        # You would add a check here and usethe user id or something to fetch
        # the other data for that user/check if they exist
        if user:
            return f(*args, **kwargs)
        return 'You aint logged in, no page for u!'

    return decorated_function


@app.route('/login')
def loginExt():
    google = oauth.create_client('google')  # create the google oauth client
    redirect_uri = url_for('authorized', _external=True)
    print(str(redirect_uri))
    return google.authorize_redirect(redirect_uri)


@app.route('/Prod/authorize')
def authorized():
    google = oauth.create_client('google')  # create the google oauth client
    token = google.authorize_access_token()  # Access token from google (needed to get user info)
    resp = google.get('userinfo')  # userinfo contains stuff u specificed in the scrope
    user_info = resp.json()
    user = oauth.google.userinfo()  # uses openid endpoint to fetch user info
    session['profile'] = user_info
    session.permanent = True  # make the session permanant so it keeps existing after broweser gets closed
    print(session)
    print(session['profile'])
    print(token)
    print(user)
    userSiesvi=None
    key = {'email': session['profile']['email']}
    print(key)
    userSiesvi=table.scan(FilterExpression=Attr("email").eq(session['profile']['email']))
    print(userSiesvi)
    #user = table.scan(FilterExpression=Attr("email").eq(session['profile']['email']))
    # table2.scan(FilterExpression=Attr("owner").eq(current_user['id']))
    if not userSiesvi:
        try:
            table.put_item(Item=({'id': session['profile']['id'], 'name': session['profile']['name'],
                                  'email': session['profile']['email']}))
            token = jwt.encode({'id': session['profile']['id'], 'exp': datetime.utcnow() + timedelta(minutes=30)},
                               app.config['SECRET_KEY'])
        except:
            return jsonify({'message': 'Try again'}), 400

        return jsonify({"message": "user entry created correctly"})
    else:
        return jsonify({"message": "user already exists"}, response_code=409)

    response = jsonify({
            'username': session['profile']['name'],
            'email': session['profile']['email'],
            'token': token.decode('UTF-8')
        })
    response.status_code = 201
    return response


@app.route('/authorize')
def authorized2():
    google = oauth.create_client('google')  # create the google oauth client
    token = google.authorize_access_token()  # Access token from google (needed to get user info)
    resp = google.get('userinfo')  # userinfo contains stuff u specificed in the scrope
    user_info = resp.json()
    user = oauth.google.userinfo()  # uses openid endpoint to fetch user info
    session['profile'] = user_info
    session.permanent = True  # make the session permanant so it keeps existing after broweser gets closed
    print(session)
    print(session['profile'])
    print(token)
    print(user)
    userSiesvi=None
    key = {'email': session['profile']['email']}
    print(key)
    userSiesvi = table.scan(FilterExpression=Attr("email").eq(session['profile']['email']))
    print(userSiesvi)#user = table.scan(FilterExpression=Attr("email").eq(session['profile']['email']))
    # table2.scan(FilterExpression=Attr("owner").eq(current_user['id']))
    if not userSiesvi['Items']:
        try:
            table.put_item(Item=({'id': session['profile']['id'], 'name': session['profile']['name'],
                                  'email': session['profile']['email']}))
            token = jwt.encode({'id': session['profile']['id'], 'exp': datetime.utcnow() + timedelta(minutes=30)},
                               app.config['SECRET_KEY'])
        except:
            return jsonify({'message': 'Try again'}), 400

        #return jsonify({"message": "user entry created correctly"})
        response = jsonify({
            'username': session['profile']['name'],
            'email': session['profile']['email'],
            'token': token.decode('UTF-8')
        })
        response.status_code = 201
        return response

    else:
        token = jwt.encode({'id': session['profile']['id'], 'exp': datetime.utcnow() + timedelta(minutes=30)},
                           app.config['SECRET_KEY'])
        #return jsonify({"message": "user already exists"}, response_code=409)
        response = jsonify({
                    'username': session['profile']['name'],
                    'email': session['profile']['email'],
                    'token': token.decode('UTF-8')
                })
        response.status_code = 201
        return response
