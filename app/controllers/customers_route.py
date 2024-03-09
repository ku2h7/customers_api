from flask import Blueprint, jsonify, request
from app.utils.database import db
from app.models.customers import Customers
from sqlalchemy.exc import SQLAlchemyError
from datetime import datetime
from flask import render_template
from flask import redirect, url_for
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
import bcrypt

customers_blueprint = Blueprint('customers_endpoint', __name__)
jwt = JWTManager()

@customers_blueprint.route('/')
def home():
    return render_template('home.html')

@customers_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    elif request.method == 'POST':
        try:
            username = request.form.get('username')
            password = request.form.get('password')

            customer = Customers.query.filter_by(username=username).first()
            if not customer or not bcrypt.checkpw(password.encode('utf-8'), customer.password.encode('utf-8')):
                return jsonify({'message': 'Invalid username or password'}), 401

            # access_token = create_access_token(identity=customer.id)
            # return jsonify({'access_token': access_token}), 200

            # Redirect to home page after successful login
            return redirect(url_for('customers_endpoint.home')) 
        except Exception as e:
            return jsonify({'error': str(e)}), 500

from flask import redirect, url_for

from flask import redirect, url_for

@customers_blueprint.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    elif request.method == 'POST':
        try:
            # Ambil data dari formulir HTML
            data = request.form

            # custom format ID 
            last_customer = Customers.query.order_by(Customers.id.desc()).first()
            if last_customer:
                last_id = last_customer.id.split('-')[-1]
                new_id = f'CUST-{str(int(last_id) + 1).zfill(10)}'
            else:
                new_id = 'CUST-0000000001'

            # Enkripsi password sebelum disimpan ke database
            hashed_password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())

            new_customer = Customers(
                id=new_id,
                name=data['name'],
                phone=data.get('phone'),
                email=data['email'],
                username=data['username'],
                password=hashed_password.decode('utf-8')
            )
            db.session.add(new_customer)
            db.session.commit()

            # return jsonify({'message': 'Customer added successfully!'}), 201

            # Redirect ke halaman login setelah pendaftaran berhasil
            return redirect(url_for('customers_endpoint.login'))

        except SQLAlchemyError as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500
        except Exception as e:
            return jsonify({'error': str(e)}), 500



@customers_blueprint.route('/profile', methods=['GET'])
@jwt_required()
def get_profile():
  try:
    current_user_id = get_jwt_identity()
    customer = Customers.query.get(current_user_id)
    if not customer:
      return jsonify({'message': 'User not found'}), 404

    return jsonify(customer.as_dict()), 200
  except Exception as e:
    return jsonify({'error': str(e)}), 500

# Tambahkan route ini jika Anda ingin mendapatkan profil spesifik user
@customers_blueprint.route('/profile/<string:id>', methods=['GET'])
@jwt_required()
def get_specific_profile(id):
    try:
        customer = Customers.query.get(id)
        if not customer:
            return jsonify({'message': 'User not found'}), 404

        return jsonify(customer.as_dict()), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@customers_blueprint.route('/customers', methods=['POST'])
def add_customer():
  try:
    data = request.json

    #custom format ID 
    last_customer = Customers.query.order_by(Customers.id.desc()).first()
    if last_customer:
      last_id = last_customer.id.split('-')[-1]
      new_id = f'CUST-{str(int(last_id) + 1).zfill(10)}'
    else:
      new_id = 'CUST-0000000001'

    #Encryption password before save to DB
    hashed_password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())

    new_customer = Customers(
      id = new_id,
      name = data['name'],
      phone = data.get('phone'),
      email = data['email'],
      username = data['username'],
      password = hashed_password.decode('utf-8') 
    )
    db.session.add(new_customer)
    db.session.commit()
    return jsonify({'message': 'Customer added successfully!'}), 201
  except SQLAlchemyError as e:
    db.session.rollback()
    return jsonify({'error': str(e)}), 500
  except Exception as e:
    return jsonify({'error': str(e)}), 500
  
@customers_blueprint.route('/bulk_customers', methods=['POST'])
def bulk_add_customer():
  try:
    data_list = request.json

    added_customers = []
    for data in data_list:
      # Custom format ID
      last_customer = Customers.query.order_by(Customers.id.desc()).first()
      if last_customer:
          last_id = last_customer.id.split('-')[-1]
          new_id = f'CUST-{str(int(last_id) + 1).zfill(10)}'
      else:
          new_id = 'CUST-0000000001'

      # Encryption password before save to DB
      hashed_password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())

      new_customer = Customers(
          id=new_id,
          name=data['name'],
          phone=data.get('phone'),
          email=data['email'],
          username=data['username'],
          password=hashed_password.decode('utf-8')
      )
      db.session.add(new_customer)
      added_customers.append(new_customer)

    db.session.commit()
    return jsonify({'message': 'Customers added successfully!', 'added_customers': [customer.id for customer in added_customers]}), 201
  except SQLAlchemyError as e:
    db.session.rollback()
    return jsonify({'error': str(e)}), 500
  except Exception as e:
    return jsonify({'error': str(e)}), 500
  
@customers_blueprint.route('/customers', methods=['GET'])
def get_customers():
  try:
    page = request.args.get('page', default=1, type=int)

    # Customer count per page, default 10
    per_page = request.args.get('per_page', default=10, type=int)
    customers = Customers.query.paginate(page=page, per_page=per_page)

    return {
      'total_customers': customers.total,
      'total_pages': customers.pages,
      'current_page': customers.page,
      'customers': [customer.as_dict() for customer in customers.items]
    }, 200
  except SQLAlchemyError as e:
    db.session.rollback()
    return jsonify({'error': str(e)}), 500
  except Exception as e:
    return jsonify({'error': str(e)}), 500

@customers_blueprint.route('/customers/<string:id>', methods=['PUT'])
def update_customer(id):
  try:
    data = request.json

    customer = Customers.query.get(id)
    if not customer:
      return jsonify({'message': 'Customer not found!'}), 404
    

    # Encryption password before update to DB
    hashed_password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())

    # Update data customer
    customer.name = data['name']
    customer.phone = data.get('phone')
    customer.email = data['email']
    customer.username = data['username']
    customer.password = hashed_password.decode('utf-8')
    customer.updated_at = datetime.utcnow()
    
    db.session.commit()
    return jsonify({'message': 'Customer updated successfully!'})
  except SQLAlchemyError as e:
    db.session.rollback()
    return jsonify({'error': str(e)}), 500
  except Exception as e:
    return jsonify({'error': str(e)}), 500
  
@customers_blueprint.route('/customers/<string:id>', methods=['DELETE'])
def delete_customer(id):
  try:
    customer = Customers.query.get(id)
    if customer:
      db.session.delete(customer)
      db.session.commit()
      return jsonify({'message': 'Customer deleted successfully!'})
    else:
      return jsonify({'message': 'Customer not found!'}), 404
  except SQLAlchemyError as e:
    db.session.rollback()
    return jsonify({'error': str(e)}), 500
  except Exception as e:
    return jsonify({'error': str(e)}), 500