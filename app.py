# app.py

from flask import Flask
from flask_restful import Resource, Api, reqparse
from flask_cors import CORS
from pred import Prediccion

app = Flask(__name__)
CORS(app)
api = Api(app)

class Result(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('url', required=True, type=str)
        args = parser.parse_args()
        url = args['url']
        print(f"POST URL recibida: {url}")
        pred = Prediccion(url)
        return {
            'url': url,
            'result': pred['resultado'],
            'probabilidad': pred['probabilidad']
        }, 200

    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument('url', required=True, type=str)
        args = parser.parse_args()
        url = args['url']
        print(f"GET URL recibida: {url}")
        pred = Prediccion(url)
        return {
            'url': url,
            'result': pred['resultado'],
            'probabilidad': pred['probabilidad']
        }, 200

api.add_resource(Result, '/result')

import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

print("🔥 Backend reiniciado correctamente")