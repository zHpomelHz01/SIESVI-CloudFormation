from datetime import datetime, timedelta
from flask import make_response
from flask_lambda import FlaskLambda
from flask import Flask, request, jsonify, render_template
import boto3
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps
import uuid
from boto3.dynamodb.conditions import Key, Attr
import pytz

app = FlaskLambda(__name__)
ddb = boto3.resource('dynamodb')
table = ddb.Table('UsersTable')
table2 = ddb.Table('ScheduleTable')
table3 = ddb.Table('Executed')
app.config['SECRET_KEY'] = 'siesviIsLovw'
app.config['CORS_HEADERS'] = 'Content-Type'
app.config['SESSION_COOKIE_NAME'] = 'google-login-session'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)


def json_response(data, response_code=200):
    response = jsonify(data)
    response.status_code = response_code
    response.headers["Content-Type"] = "application/json"
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, DELETE, PUT, PATCH, OPTIONS"

    return response


def checkParameters(parameters_requiredch=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            datosOb = None
            if request.method == 'POST' or request.method == 'PUT':
                if 'application/json' == request.headers['Content-Type']:  # request.headers:
                    datosOb = request.get_json()
                    parameters_required = parameters_requiredch
                    for parameter in parameters_required:
                        try:
                            print(datosOb[parameter])
                        except:
                            return jsonify({'message': 'Missing parameter :' + str(parameter)}), 422
                    datosOb['extra'] = kwargs
                    return f(datosOb)
                if not datosOb:
                    return jsonify({'message': 'Formato incorrecto'}), 400
            else:
                return f({'extra': kwargs})

        return decorated_function

    return decorator


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):

        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], 'HS256')
            current_user = table.get_item(Key={'id': data['id']}).get('Item')
        except AssertionError as error:
            return jsonify({'message': 'Token is invalid!'}), 402
        except jwt.ExpiredSignature:
            return jsonify({'message': 'Token is expired!'}), 403
        # except jwt.exceptions.DecodeError:

        return f(current_user, *args, **kwargs)

    return decorated


@app.route('/')
def root():
    data = {
        "message": "Welcome API SIESVI"
    }
    return json_response(data, response_code=200)


@app.route('/users/signup', methods=['POST'])
@checkParameters(["id", "name", "age", "email", "password"])
def create_user(res):
    # user = None
    # key = {'id': res['id']}
    # user = table.get_item(Key=key).get('Item')
    user = table.scan(FilterExpression=Attr("id").eq(res['id']) | Attr("email").eq(res['email']))
    # table2.scan(FilterExpression=Attr("owner").eq(current_user['id']))
    if not user['Items']:
        hashed_password = generate_password_hash(res['password'], method='sha256')
        try:
            table.put_item(Item=({'id': res['id'], 'name': res['name'], 'age': res['age'],
                                  'email': res['email'], 'password': hashed_password}))
        except:
            return jsonify({'message': 'Try again'}), 400

        return json_response({"message": "user entry created correctly"})
    else:
        return json_response({"message": "user already exists"}, response_code=409)


@app.route('/users/login', methods=['POST'])
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    key = {'id': auth.username}
    user = table.get_item(Key=key).get('Item')
    # user = table.scan(ConditionExpression=Attr("id") .eq(current_user['id']) | Attr("email").eq(current_user['email']))
    # user=ConditionExpression=Attr("holder").eq(caller) | Attr('lockname').not_exists()
    print(user)
    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})
    try:
        print(user['password'])
    except:
        return jsonify({'message': 'Bad request :' + str(parameter)}), 422
    if check_password_hash(user['password'], auth.password):
        request.get_json()
        token = jwt.encode({'id': user['id'], 'exp': datetime.utcnow() + timedelta(minutes=30)},
                           app.config['SECRET_KEY'])
        response = jsonify({
            'username': user['name'],
            'email': user['email'],
            'token': token.decode('UTF-8')
        })
        response.status_code = 201
        return response

    return make_response('Could not verify _a', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})


@app.route('/schedule', methods=['POST', 'GET'])
@checkParameters(['latitud', 'longitud', 'execution_date'])
@token_required
def create_schedule_point(current_user, datos):
    if request.method == 'POST':
        try:
            input = pytz.utc.normalize(pytz.timezone("America/Mexico_City").localize(datetime.strptime(datos['execution_date'], '%d/%m/%y %H:%M')))
        except:
            return jsonify({'message': 'wrong format'}), 422
        base = pytz.utc.normalize(datetime.now(pytz.timezone('America/Mexico_City')))
        max = base + timedelta(days=10)
        if (base < input and input < max):
            table2.put_item(Item={'id': str(uuid.uuid5(uuid.NAMESPACE_X500, current_user['id'] + str(datetime.now()))),
                                  'owner': current_user['id'],
                                  'latitud': str(datos['latitud']),
                                  'longitud': str(datos['longitud']), 'creation date': str(datetime.now()),
                                  'execution_date': input.strftime("%d/%m/%Y %H:%M")})

            return json_response({"message": "successful task"})
        else:
            return json_response({"message": "invalid date"}, response_code=402)
    elif request.method == 'GET':
        datos = request.get_json()
        schedules = []
        executed = []
        schedules = table2.scan(FilterExpression=Attr("owner").eq(current_user['id']))
        executed = table3.scan(FilterExpression=Attr("owner").eq(current_user['id']))
        return json_response(schedules['Items'] + executed['Items'])


@app.route('/schedule/<scheduleID>', methods=['GET', 'PUT', 'DELETE'])
@checkParameters(['latitud', 'longitud', 'execution_date'])
@token_required
def get_patch_delete_schedule(current_user, datos):
    key = {'id': datos['extra']['scheduleID']}
    task = table2.get_item(Key=key).get('Item')
    if request.method == 'GET':
        if task:
            return json_response(str(task))
        else:
            task = table3.get_item(Key=key).get('Item')
            if task:
                return json_response(str(task))
            else:
                return json_response({"message": "task entry not found"}, response_code=404)
    elif task:
        if request.method == 'PUT':
            input = pytz.utc.normalize(
                pytz.timezone("America/Mexico_City").localize(
                    datetime.strptime(datos['execution_date'], '%d/%m/%y %H:%M')))
            base = pytz.utc.normalize(datetime.now(pytz.timezone('America/Mexico_City')))
            max = base + timedelta(days=10)
            if (base < input and input < max):

                attribute_updates = {
                    'latitud': {'Value': str(datos['latitud']), 'Action': 'PUT'},
                    'longitud': {'Value': str(datos['longitud']), 'Action': 'PUT'},
                    'execution_date': {'Value': input.strftime("%d/%m/%Y %H:%M"), 'Action': 'PUT'}}

                table2.update_item(Key=key, AttributeUpdates=attribute_updates)
                return json_response({"message": "successful task"})
            else:
                return json_response({"message": "invalid date"}, response_code=402)

            return json_response({"message": "user entry updated"})
        else:
            table2.delete_item(Key=key)
            return json_response({"message": "task entry deleted"})
    else:
        return json_response({"message": "task entry not found"}, response_code=404)


@app.route('/users/<id>', methods=['GET', 'PATCH', 'DELETE'])
@token_required
def get_patch_delete_user(id):
    key = {'id': id}
    if request.method == 'GET':
        user = table.get_item(Key=key).get('Item')
        if user:
            return json_response(user)
        else:
            return json_response({"message": "user not found"}, 404)
    elif request.method == 'PATCH':
        attribute_updates = {key: {'Value': value, 'Action': 'PUT'}
                             for key, value in request.form.items()}
        table.update_item(Key=key, AttributeUpdates=attribute_updates)
        return json_response({"message": "user entry updated"})
    else:
        table.delete_item(Key=key)
        return json_response({"message": "user entry deleted"})


if __name__ == '__main__':
    app.run(debug=True)