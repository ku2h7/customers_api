from app.utils.database import db
from datetime import datetime

class Customers(db.Model):
  id = db.Column(db.String(20), primary_key=True)
  name = db.Column(db.String(20), nullable=False)
  phone = db.Column(db.String(20), nullable=True)
  email = db.Column(db.String(100), nullable=False)
  username = db.Column(db.String(100), nullable=False)
  password = db.Column(db.String(100), nullable=False)
  created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
  updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

  def as_dict(self):
    return {
      "id": self.id,
      "name": self.name,
      "phone": self.phone,
      "email": self.email,
      "username": self.username,
      "password": self.password,
      "created_at": self.created_at,
      "updated_at": self.updated_at
    }