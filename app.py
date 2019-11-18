import datetime
from time import mktime

from flask import Flask, request
import jwt
import requests

from secrets import api_auth_token, jwt_secret_key
from utils import parse_date_time
import business

app = Flask(__name__)


def decode_auth_token(auth_token):
    # use jwt, jwt_secret_key
    # should be a one liner, but we want you to see how JWTs work
    return jwt.decode(auth_token, key=jwt_secret_key)


def encode_auth_token(user_id, name, email, scopes):
    # use jwt, jwt_secret_key
    # use the following payload:
    # { 'sub': user_id, 'name': name, 'email': email, 'scope': scopes, 'exp': mktime((datetime.now() + timedelta(days=1)).timetuple()) }
    # should be a one liner, but we want you to see how JWTs work
    # remember to convert the token to string, use .decode("utf-8") rather than str() for this
    return jwt.encode(payload={ 'sub': user_id, 'name': name, 'email': email, 'scope': scopes, 'exp': mktime((datetime.datetime.now() + datetime.timedelta(days=1)).timetuple())}, key=jwt_secret_key).decode("utf-8")


def get_user_from_token():
    # use decode_auth_token above and flask.request imported above
    # should pull token from the Authorization header
    # Authorization: Bearer {token}
    # Where {token} is the token created by the login route
    auth_header: str = request.headers.get('Authorization')
    if not auth_header:
        raise { 'code': 400, 'message': 'Authorization header is required'}
    if not auth_header.startswith('Bearer '):
        raise { 'code': 400, 'message': 'Authorization header must be a bearer token'}
    auth_token = auth_header.split(' ')[1]
    return decode_auth_token(auth_token)


@app.route('/')
def status():
    return 'API Is Up'


@app.route('/user', methods=['GET'])
def user():
    # get the user data from the auth/header/jwt
    try:
        return get_user_from_token()
    except dict as error:
        return error['message'], error['code']

@app.route('/login', methods=['POST'])
def login():
    # use use flask.request to get the json body and get the email and scopes property
    # use the business.login function to get the user data
    # return a the encoded json web token as a token property on the json response as in the format below
    # we're not actually validitating a password or anything because that would add unneeded complexity
    if request.content_type != 'application/json' or not str(request.json):
        return f'JSON object body required ({request.content_type}, {request.json})', 400
    if not request.json.get('email'):
        return 'email parameter is required', 400
    email = request.json.get('email')
    scopes = request.json.get('scopes')
    user = business.login(email)
    return {
        'token': encode_auth_token(user_id=user['id'], name=user['name'], email=user['email'], scopes=scopes)
    }


@app.route('/widgets', methods=['GET'])
def widgets():
    # accept the following optional query parameters (using the the flask.request object to get the query params)
    # type, created_start, created_end
    # dates will be in iso format (2019-01-04T16:41:24+0200)
    # dates can be parsed using the parse_date_time function written and imported for you above
    # get the user ID from the auth/header
    # verify that the token has the widgets scope in the list of scopes

    # Using the requests library imported above send the following the following request,

    # GET https://us-central1-interview-d93bf.cloudfunctions.net/widgets?user_id={user_id}
    # HEADERS
    # Authorization: apiKey {api_auth_token}

    # the api will return the data in the following format

    # [ { "id": 1, "type": "floogle", "created": "2019-01-04T16:41:24+0200" } ]
    # dates can again be parsed using the parse_date_time function

    # filter the results by the query parameters
    # return the data in the format below

    try:
        user = get_user_from_token()
    except dict as error:
        return error['message'], error['code']

    type = request.args.get('type', None)
    created_start = request.args.get('created_start', None)
    created_end = request.args.get('created_end', None)

    user_id = user['sub']

    url = f'https://us-central1-interview-d93bf.cloudfunctions.net/widgets?user_id={user_id}'

    resp = requests.get(url, headers={'Authorization': f'apiKey {api_auth_token}'})
    if resp.status_code != 200:
        return resp.text, resp.status_code
    results = resp.json()
    print(results)

    return {
        'total_widgets_own_by_user': 2,
        'matching_items': [
            {
                "id": r.get('id'),
                "type": r.get('type'),
                "type_label": r.get('type', '').replace('-', ' ').title(),
                "created": r.get('created'),
            }
            for r in results
            if (not type or type == r.get('type')) and
               (not created_start or created_start <= r.get('created')) and
               (not created_end or created_end >= r.get('created'))
        ]
    }


if __name__ == '__main__':
    app.run()
