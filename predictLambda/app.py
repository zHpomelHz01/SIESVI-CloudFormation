import requests
from flask_lambda import FlaskLambda
from flask import request, jsonify
import pickle
from boto3.dynamodb.conditions import Key, Attr
import boto3
from functools import wraps
import datetime
import jwt
from io import BytesIO
import json
import math
import secrets

ddb = boto3.resource('dynamodb')
tabla_clima = ddb.Table('Weather')
userTable = ddb.Table('UsersTable')

app = FlaskLambda(__name__)
app.config['CORS_HEADERS'] = 'Content-Type'
app.config['SECRET_KEY'] = 'siesviIsLovw'

mapa_densidad_poblacional = {
    "MIGUEL HIDALGO": 8927.8, "MILPA ALTA": 511.9, "AZCAPOTZALCO": 12892.8,
    "CUAJIMALPA": 3059.2, "TLALPAN": 2225.5, "GUSTAVO A MADERO": 13347.8,
    "GUSTAVO A. MADERO": 13347.8, "VENUSTIANO CARRANZA": 13102.8,
    "MAGDALENA CONTRERAS": 3904.6, "IZTACALCO": 17522.7, "CUAUHTEMOC": 16783.6,
    "XOCHIMILCO": 3874.8, "TLAHUAC": 4569.7, "BENITO JUAREZ": 16259.2,
    "IZTAPALAPA": 16219.6, "ALVARO OBREGON": 7916.4, "COYOACAN": 11395
}

mapa_categoria_velocidad = {
    "SECONDARY": 50, "RESIDENTIAL": 30, "PRIMARY": 80, "TERTIARY": 40, "TRUNK": 20,
    "MOTORWAY": 40, "SERVICE": 20, "CYCLEWAY": 10, "UNCLASSIFIED": 30, "FOOTWAY": 30,
    "PEDESTRIAN": 30, "LIVING_STREET": 30, "TRUNK_LINK": 30, "BUS_STOP": 10,
    "MOTORWAY_LINK": 10, "STEPS": 10, "PATH": 10, "TRACK": 40, "RACEWAY": 10,
    "CORRIDOR": 80, "SECONDARY_LINK": 40, "CONSTRUCTION": 20, "PRIMARY_LINK": 50,
    "NEIGHBOURHOOD": 30, "ADMINISTRATIVE": 10, "SERVICES": 10, "VILLAGE": 10,
    "TERTIARY_LINK": 30, "TOWN": 40
}

columns = [
    'Unnamed: 0', 'id_consultaOpenStreetMap', 'latitud', 'longitud', 'delegacion', 'densidad_poblacional',  # 5
    'velocidad_maxima', 'fecha', 'dia_anio', 'es_puente', 'dia_sem',
    'dia_mes', 'mes', 'anio', 'epoca_dia', 'hora_dia',
    'incidente', 'estacion', 'RH', 'TMP', 'WDR',
    'WSP', 'Temp_Avg', 'RH_Avg', 'WSpeed_Avg', 'WSpeed_Max',
    'WDir_Avg', 'WDir_SD', 'Rain_Tot', 'Press_Avg', 'Rad_Avg'
]

val_columns = [2, 3, 5, 6, 8, 10, 11, 12, 13, 15, 18, 19, 20, 21, 22, 23, 24, 28, 29]
columns_ = []

for i in val_columns:
    columns_.append(columns[i])


def json_response(data, response_code=200):
    response = jsonify(data)
    response.status_code = response_code
    response.headers["Content-Type"] = "application/json"
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, DELETE, PUT, PATCH, OPTIONS"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Allow-Headers"] = "authorization, x-access-token"
    response.headers["Access-Control-Request-Headers"] = "authorization, x-access-token"
    return response


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):

        token = None

        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                token = auth_header.split(" ")[1]
            except IndexError:

                return json_response({'message': 'Bearer token malformed.'}, response_code=401)
        else:
            return json_response({'message': 'Token is missing!'}, response_code=401)
        if not token:
            return json_response({'message': 'Token is missing!'}, response_code=401)
        try:
            print(token)
            data = jwt.decode(token, app.config['SECRET_KEY'], 'HS256')
            current_user = userTable.get_item(Key={'id': data['id']}).get('Item')
        except AssertionError as error:
            return json_response({'message': 'Token is invalid!'}, response_code=401)
        except jwt.ExpiredSignature:
            return json_response({'message': 'Token is expired!'}, response_code=401)
        return f(current_user, *args, **kwargs)

    return decorated


@app.route('/predict_api', methods=['POST'])
@token_required
def predict_api(current_user):
    data = request.get_json()
    l = []
    if str(type(data)) == "<class 'list'>":
        l = list(map(predict_point, data))
    elif str(type(data)) == "<class 'dict'>":
        l.append(predict_point(data))
    else:
        return json_response({'message': 'Body are invalid!'}, 400)
    return json_response(l)


@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    l = []
    if str(type(data)) == "<class 'list'>":
        aux_ruta = list(data)
        aux_ruta.pop(0)
        aux_ruta.append(data[-1])
        nueva_ruta = list(map(distancia, zip(data, aux_ruta)))
        pp = list(map(lambda x: x['distanciaPuntoSig'], nueva_ruta))
        for i in range(0, len(nueva_ruta)):
            nueva_ruta[i]['distanciaTotal'] = sum(pp[0:i])

        l = list(map(predict_point, nueva_ruta))
    elif str(type(data)) == "<class 'dict'>":
        l.append(predict_point(data))
    else:
        return json_response({'message': 'Body are invalid!'}, 400)
    return json_response(l)


def haversine(lon1, lat1, lon2, lat2):
    from math import radians, cos, sin, asin, sqrt
    lon1, lat1, lon2, lat2 = map(radians, [lon1, lat1, lon2, lat2])

    dlon = lon2 - lon1
    dlat = lat2 - lat1
    a = sin(dlat / 2) ** 2 + cos(lat1) * cos(lat2) * sin(dlon / 2) ** 2
    c = 2 * asin(sqrt(a))

    meters = 6371 * c * 1000
    return meters + (.15) * meters


def distancia(X):
    (A, B) = X
    d = haversine(A['longitud'], A['latitud'], B['longitud'], B['latitud'])
    A['distanciaPuntoSig'] = d
    return A


def variablesClima2(fecha_string):
    request = tabla_clima.scan(FilterExpression=Attr("TimeStamp").eq(fecha_string))
    registros = request['Items']
    print(registros)
    registro = registros[0]
    return registro['Temp_Avg'], registro['RH_Avg'], registro['WSpeed_Avg'], registro['Rain_Tot'], registro['Press_Avg']
"""
* Using the API openweathermap to get data of the weather on the point
"""


def variablesClima(lat, lon):
    url = 'https://api.openweathermap.org/data/2.5/weather?lat={}&lon={}&appid='+secrets.apikey+'&units=metric'.format(
        lat, lon)
    r = requests.get(url).json()
    try:
        velocidad_viento = r['wind']['speed']
        direccion_viento = r['wind']['deg']
        temp = r['main']['temp'] - 273.15
        temp_avg = (r['main']['temp_min'] + r['main']['temp_max']) / 2 - 273.15
        pression = r['main']['pressure']
        humidity = r['main']['humidity']
        return temp, temp_avg, velocidad_viento, direccion_viento, pression, humidity
    except:
        return 0, 0, 0, 0, 0, 0

"""
* Model of variables of Time to map the time into day of the year(1-365), day of the week (1-7), day of the month (1-31)
* month (1-12), year and hour
"""


def variablesTiempo(dt):
    dia_anio = int(dt.strftime("%j"))
    dia_sem = dt.weekday() + 1
    dia_mes = dt.day
    mes = dt.month
    anio = dt.year
    hora_dia = dt.hour
    return dia_anio, dia_sem, dia_mes, mes, anio, hora_dia
# ----
# Get prediction on 1 point 
# Inputs: Point [latitude, longitude]
# Outputs: all Data on that point
# ----
def predict_point(point):
    lat = point['latitud']
    lon = point['longitud']
    distancia = point['distanciaTotal']

    urlCity = 'https://nominatim.openstreetmap.org/reverse?format=jsonv2&lat={}&lon={}'.format(lat, lon)
    r = requests.get(str(urlCity)).json()

    try:
        city = r['address']['city']
        delegacion = str(r['address']['neighbourhood']).upper().replace('Á', 'A').replace('É', 'E').replace('Í',
                                                                                                            'I').replace(
            'Ó', 'O').replace('Ú', 'U')
        category = str(r['type']).upper().replace('Á', 'A').replace('É', 'E').replace('Í', 'I').replace('Ó',
                                                                                                        'O').replace(
            'Ú', 'U')

        velocidad_maxima = mapa_categoria_velocidad[category] if category in mapa_categoria_velocidad else 40
        densidad_poblacional = mapa_densidad_poblacional[
            delegacion] if delegacion in mapa_densidad_poblacional else 9532.1
    except:
        return {'Mensaje': 'Coordenadas inválidas', 'latitud': lat, 'longitud': lon}

    if city != 'Ciudad de México':
        return {'Mensaje': 'Coordenadas inválidas', 'latitud': lat, 'longitud': lon}
    else:
        fecha_ahora = datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=-6)))
        minutos = math.ceil((distancia / (8.9)) / 60)
        fecha_ahora = fecha_ahora + datetime.timedelta(minutes=minutos)
        fecha_ahora = fecha_ahora.replace(day=16)

        # fecha_ahora = fecha_ahora + datetime.timedelta(days=1)######################Quitar

        fecha_ahora_string = fecha_ahora.strftime("%Y-%m-%d %H:%M:00")

        temp, temp_avg_, velocidad_viento, direccion_viento, pression, RH = variablesClima(lat, lon)
        dia_anio, dia_sem, dia_mes, mes, anio, hora_dia = variablesTiempo(fecha_ahora)
        print(fecha_ahora_string)
        Temp_avg, RH_avg, wspeed_avg, rain_tot, press_avg = variablesClima2(fecha_ahora_string)

    dataCom = {
        'latitud': lat,
        'longitud': lon,
        'densidad_poblacional': densidad_poblacional,
        'velocidad_maxima': velocidad_maxima,
        'dia_anio': dia_anio,
        'dia_sem': dia_sem,
        'dia_mes': dia_mes,
        'mes': mes,
        'anio': anio,
        'hora_dia': hora_dia,
        'RH': RH,
        'TMP': temp,
        'WDR': direccion_viento,
        'WSP': velocidad_viento,
        'Temp_Avg': Temp_avg,
        'RH_Avg': RH_avg,
        'WSpeed_Avg': wspeed_avg,
        'Rain_Tot': rain_tot,
        'Press_Avg': press_avg,
        'fecha': fecha_ahora_string
    }
    print('--------------------')
    print(dataCom)

    r = requests.post(f"http://34.229.84.240:5000/predice", data=json.dumps(car),
                      headers={'Content-Type': 'application/json'})
    respuesta = r.json()

    return respuesta


if __name__ == '__main__':
    app.run(debug=True)
