from functools import wraps
from flask import request, g, jsonify
from helperfunctions import *


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        response_dict = {"statusCode": "", "message": "", "data": {}}
        token = None
        if "Authorization" in request.headers:
            token = request.headers["Authorization"].split(" ")[-1]
        if not token:
            response_dict["data"] = {}
            response_dict["message"] = "Authentication Token is missing!"
            response_dict["statusCode"] = 401
            return jsonify(response_dict)
        try:
            data = decode_jwt_token(token)
            g.token = data
            # check = check_id(cursor, logger, id)
        except Exception as e:
            response_dict["data"] = {}
            response_dict["message"] = "Something went wrong: " + str(e)
            response_dict["statusCode"] = 500
            return jsonify(response_dict)

        return f(*args, **kwargs)

    return decorated
