import yaml
from flask import Flask
from flask_jwt_extended import JWTManager
from app.utils.database import db
from app.controllers import customers_route

# Membaca konfigurasi dari railway.yaml
with open('railway.yaml', 'r') as file:
    config = yaml.safe_load(file)

DATABASE_TYPE = config['plugins']['python']['env']['DATABASE_TYPE']
DATABASE_USERNAME = config['plugins']['python']['env']['DATABASE_USERNAME']
DATABASE_PASSWORD = config['plugins']['python']['env']['DATABASE_PASSWORD']
DATABASE_HOST = config['plugins']['python']['env']['DATABASE_HOST']
DATABASE_PORT = config['plugins']['python']['env']['DATABASE_PORT']
DATABASE_NAME = config['plugins']['python']['env']['DATABASE_NAME']
SECRET_KEY = config['plugins']['python']['env']['SECRET_KEY']
PORT = config['plugins']['python']['port']

# Konfigurasi aplikasi Flask
app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = f"{DATABASE_TYPE}://{DATABASE_USERNAME}:{DATABASE_PASSWORD}@{DATABASE_HOST}:{DATABASE_PORT}/{DATABASE_NAME}"

jwt = JWTManager(app)
db.init_app(app)

app.register_blueprint(customers_route.customers_blueprint, url_prefix="/v1")

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=PORT)
