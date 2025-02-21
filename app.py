from flask import Flask, render_template, redirect, url_for, flash, request, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename

import os

# Initialize Flask App
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Change this to a strong secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'your_default_secret_key')

app.secret_key = 'your_secret_key_here'

# Initialize Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Redirect if not logged in


# User Model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)  # Admin flag
# Cart Model
class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    food_name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    quantity = db.Column(db.Integer, default=1)

# Define MenuItem model
class MenuItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)

# Load User for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Home Route (Updated to pass username)
@app.route('/')
def home():
    return render_template('index.html', user=current_user if current_user.is_authenticated else None)

@app.route('/about-us')
def about_us():
    return render_template('about_us.html')

@app.route('/terms_and_conditions')
def terms_and_conditions():
    return render_template('terms_and_conditions.html')

@app.route('/menu')
def menu():
    menu_items = MenuItem.query.all()  # Fetch all food items from the database
    return render_template('menu.html', menu_items=menu_items)

# Register Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        is_admin = 'is_admin' in request.form  # If checkbox is checked, make admin

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered! Try logging in.', 'danger')
            return redirect(url_for('login'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, email=email, password=hashed_password, is_admin=is_admin)
        db.session.add(user)
        db.session.commit()

        flash('Account created successfully!', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')
 
@app.route('/offers')
def offers():
    return render_template('offers.html')


@app.route('/more-food')
def more_food():
    return render_template('more_food.html', user=current_user if current_user.is_authenticated else None)

# Login Route (Now redirects to home after login)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))  # Redirect admin
            else:
                return redirect(url_for('home'))  # Normal users go to home
        else:
            flash('Login failed! Check your credentials.', 'danger')

    return render_template('login.html')

@app.route('/admin-dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        return redirect(url_for('home'))
    return render_template('admin_dashboard.html')

@app.route('/admin/manage-menu', methods=['GET', 'POST'])
@login_required
def manage_menu():
    if not current_user.is_admin:
        return redirect(url_for('home'))
    if request.method == 'POST':
        name = request.form.get('name')
        price = request.form.get('price')
        new_item = MenuItem(name=name, price=float(price))
        db.session.add(new_item)
        db.session.commit()
        flash("Menu item added successfully!", "success")
    menu_items = MenuItem.query.all()
    return render_template('admin_manage_menu.html', menu_items=menu_items)

@app.route('/admin/manage-users')
@login_required
def manage_users():
    if not current_user.is_admin:
        return redirect(url_for('home'))
    users = User.query.all()
    return render_template('admin_manage_users.html', users=users)

@app.route('/admin/manage-offers')
@login_required
def manage_offers():
    if not current_user.is_admin:
        return redirect(url_for('home'))
    return render_template('admin_manage_offers.html')


# Logout Route (Redirects to home)
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'info')
    return redirect(url_for('home'))

@app.route('/cart')
@login_required
def cart():
    return render_template('cart.html')

# Function to get item details by ID (Assume a function exists)
def get_item_by_id(item_id):
    return {'id': item_id, 'name': f'Item {item_id}', 'price': 100}

@app.route('/add_to_cart', methods=['POST'])
def add_to_cart():
    data = request.get_json()
    item_id = data['item_id']
    cart = session.get('cart', [])

    for cart_item in cart:
        if cart_item['id'] == item_id:
            cart_item['quantity'] += 1
            break
    else:
        item = get_item_by_id(item_id)
        item['quantity'] = 1
        cart.append(item)

    session['cart'] = cart
    total = sum(item['price'] * item['quantity'] for item in cart)
    return jsonify({'cart_items': cart, 'total': total})


# Route to delete a user
@app.route('/admin/delete-user/<int:user_id>')
def delete_user(user_id):
    if not current_user.is_authenticated or not current_user.is_admin:
        return redirect(url_for('home'))
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
    return redirect(url_for('manage_users'))


# Route to delete a menu item
@app.route('/admin/delete-menu-item/<int:item_id>')
def delete_menu_item(item_id):
    if not current_user.is_authenticated or not current_user.is_admin:
        return redirect(url_for('home'))
    item = MenuItem.query.get(item_id)
    if item:
        db.session.delete(item)
        db.session.commit()
    return redirect(url_for('manage_menu'))

@app.route('/admin/add-offer', methods=['POST'])
def add_offer():
    if not current_user.is_authenticated or not current_user.is_admin:
        return redirect(url_for('home'))
    
    title = request.form.get('title')
    discount = request.form.get('discount')

    new_offer = Offer(title=title, discount=discount)
    db.session.add(new_offer)
    db.session.commit()

    return redirect(url_for('manage_offers'))

# Route to delete an offer
@app.route('/admin/delete-offer/<int:offer_id>')
def delete_offer(offer_id):
    if not current_user.is_authenticated or not current_user.is_admin:
        return redirect(url_for('home'))
    offer = Offer.query.get(offer_id)
    if offer:
        db.session.delete(offer)
        db.session.commit()
    return redirect(url_for('manage_offers'))


@app.route('/remove_from_cart', methods=['POST'])
def remove_from_cart():
    data = request.get_json()
    item_id = data['item_id']
    cart = session.get('cart', [])

    cart = [item for item in cart if item['id'] != item_id]
    session['cart'] = cart
    total = sum(item['price'] * item['quantity'] for item in cart)
    return jsonify({'cart_items': cart, 'total': total})


# Add item to cart (or update quantity)
@app.route('/update_cart', methods=['POST'])
@login_required
def update_cart():
    data = request.json
    food_name = data['food_name']
    price = data['price']
    quantity = data['quantity']
    user_id = current_user.id  # Ensure user is logged in

    # Check if item is already in the cart
    cart_item = Cart.query.filter_by(user_id=user_id, food_name=food_name).first()
    if cart_item:
        cart_item.quantity = quantity  # Update quantity
    else:
        new_item = Cart(user_id=user_id, food_name=food_name, price=price, quantity=quantity)
        db.session.add(new_item)

    db.session.commit()
    return jsonify({"message": "Cart updated successfully!"})


# Fetch cart items for the logged-in user
@app.route('/get_cart', methods=['GET'])
@login_required
def get_cart():
    user_id = current_user.id
    cart_items = Cart.query.filter_by(user_id=user_id).all()

    
    cart_data = [{"food_name": item.food_name, "price": item.price, "quantity": item.quantity} for item in cart_items]
    return jsonify(cart_data)

# Create database tables before running the app
with app.app_context():
    db.create_all()  # Ensure the database and tables are created

def add_is_admin_column():
    with app.app_context():
        from sqlalchemy.exc import OperationalError
        try:
            # Try querying the column to check if it exists
            db.session.execute('SELECT is_admin FROM user')
        except OperationalError:
            # If column doesn't exist, add it
            db.session.execute('ALTER TABLE user ADD COLUMN is_admin BOOLEAN DEFAULT 0')
            db.session.commit()
            print("✅ Column 'is_admin' added successfully!")

from sqlalchemy import text

def add_is_admin_column():
    with app.app_context():
        from sqlalchemy.exc import OperationalError
        try:
            # Check if 'is_admin' exists
            db.session.execute(text('SELECT is_admin FROM "user" LIMIT 1'))
        except OperationalError:
            # Add 'is_admin' column if it doesn't exist
            db.session.execute(text('ALTER TABLE "user" ADD COLUMN is_admin BOOLEAN DEFAULT 0'))
            db.session.commit()
            print("✅ Column 'is_admin' added successfully!")

# Call this function when the app starts
add_is_admin_column()


# Run Flask App
if __name__ == '__main__':
    app.run(debug=True)
