from sqlalchemy.dialects.postgresql import JSONB
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
db = SQLAlchemy()

# Define the Role data-model
class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    #Defines the relationship with the "User" table/class
    #Along with 'roles' in 'User' forms bidirectional relationship
    user = db.relationship('User', back_populates='roles') #'uselist' is not used here as I want multiple user to have 'admin'/'customer' role.

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id', ondelete='CASCADE'))
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=True)
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    profile_picture = db.Column(db.String(255), nullable=True)

    #Defines the relationship with the "Role" table/class
    #Along with 'user' in 'Role' forms bidirectional relationship
    roles = db.relationship('Role', back_populates='user', uselist=False) #'uselist' ensures that each user can have at most one role.
    orders = db.relationship('Order', back_populates='user')
    
class Order(db.Model):
    __tablename__ = 'orders'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    total_price = db.Column(db.Float, nullable=False)

    user = db.relationship('User', back_populates='orders', uselist=False) #'uselist' ensures that each order can be associated with only one user.
    order_items = db.relationship('OrderItems', back_populates='order')


class OrderItems(db.Model):
    __tablename__ = 'order_items'
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    order_id = db.Column(db.Integer, db.ForeignKey('orders.id', ondelete='CASCADE'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    total = db.Column(db.Float, nullable=False)

    product = db.relationship('Product', back_populates='order_items')
    order = db.relationship('Order', back_populates='order_items')


class Product(db.Model):
    __tablename__ = 'products'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True, nullable=False)
    stock = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    image = db.Column(db.String(255), nullable=False)
    details = db.Column(JSONB)

    order_items = db.relationship('OrderItems', back_populates='product')
    categories = db.relationship('Category', secondary='product_categories')


class Category(db.Model):
    __tablename__ = 'categories'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), unique=True, nullable=False)

class ProductCategory(db.Model):
    __tablename__ = 'product_categories'
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id', ondelete='CASCADE'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('categories.id', ondelete='CASCADE'), nullable=False)