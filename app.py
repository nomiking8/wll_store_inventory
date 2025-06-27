import os
from datetime import timedelta, datetime
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, make_response, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField, SubmitField, SelectField, IntegerField, TextAreaField
from wtforms.validators import DataRequired, Optional
from html import escape
import logging
import re
import pandas as pd
from io import BytesIO
import pytz
from uuid import uuid4
from werkzeug.security import check_password_hash
import psycopg2

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['DEBUG'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24).hex())
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

# Initialize database
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Configure logging
logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Valid categories and item types
VALID_CATEGORIES = ['IDU', 'ODU', 'Power', 'General', 'Other']
VALID_ITEM_TYPES = ['IDU', 'ODU', 'Power', 'General', 'Other']
VALID_DOMAINS = ['Chakwal', 'Jhelum']

# Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class AddInventoryForm(FlaskForm):
    domain = SelectField('Domain', choices=[('', 'Select Domain')] + [(dom, dom) for dom in VALID_DOMAINS], validators=[Optional()])
    category = SelectField('Category', choices=[('', 'Select Category')] + [(cat, cat) for cat in VALID_CATEGORIES], validators=[DataRequired()])
    item_type = SelectField('Item Type', choices=[('', 'Select Item Type')] + [(type, type) for type in VALID_ITEM_TYPES], validators=[DataRequired()])
    item_name = StringField('Item Name', validators=[DataRequired()])
    serial_number = StringField('Serial Number', validators=[DataRequired()])
    license_power_capacity = StringField('License/Power Capacity', validators=[Optional()])
    band = StringField('Band', validators=[Optional()])
    frequency_range = StringField('Frequency Range', validators=[Optional()])
    item_in_stock = IntegerField('Item in Stock', validators=[Optional()], default=1)
    moved_from = StringField('Moved From', validators=[Optional()])
    moved_to = StringField('Moved To', validators=[Optional()])
    vendor = StringField('Vendor', validators=[Optional()])
    other_item_type = StringField('Specify Other Item Type', validators=[Optional()])
    submit = SubmitField('Submit')

class AddDRSLinkForm(FlaskForm):
    domain = SelectField('Domain', choices=[('', 'Select Domain')] + [(dom, dom) for dom in VALID_DOMAINS], validators=[Optional()])
    link_name = StringField('Link Name', validators=[DataRequired()])
    site_name = StringField('Site Name', validators=[Optional()])
    site_id = StringField('Site ID', validators=[Optional()])
    site_lic = StringField('Site License', validators=[Optional()])
    site_type = StringField('Site Type', validators=[Optional()])
    link_vendor = StringField('Link Vendor', validators=[Optional()])
    tx_freq = StringField('TX Frequency', validators=[Optional()])
    rx_freq = StringField('RX Frequency', validators=[Optional()])
    tx_power = StringField('TX Power', validators=[Optional()])
    mrmc_profile = StringField('MRMC Profile', validators=[Optional()])
    vlan_numbers = TextAreaField('VLAN Numbers', validators=[Optional()])
    ports = TextAreaField('Ports', validators=[Optional()])
    e1_ports = TextAreaField('E1 Ports', validators=[Optional()])
    link_ips = TextAreaField('Link IPs', validators=[Optional()])
    link_capacity = StringField('Link Capacity', validators=[Optional()])
    link_license = StringField('Link License', validators=[Optional()])
    link_license_key = StringField('Link License Key', validators=[Optional()])
    idu_sn = StringField('IDU Serial Number', validators=[Optional()])
    odu_sn = StringField('ODU Serial Number', validators=[Optional()])
    dish_size = StringField('Dish Size', validators=[Optional()])
    tower_height = StringField('Tower Height', validators=[Optional()])
    dish_height = StringField('Dish Height', validators=[Optional()])
    remarks = TextAreaField('Remarks', validators=[Optional()])
    submit = SubmitField('Submit')

# Helper functions
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def safe_float(value, field_name):
    try:
        return float(value) if value.strip() else None
    except ValueError:
        raise ValueError(f"Invalid numeric value for {field_name}: {value}")

def safe_int(value, field_name):
    try:
        return int(value) if value.strip() else None
    except ValueError:
        raise ValueError(f"Invalid integer value for {field_name}: {value}")

def sanitize_text(value):
    return escape(value.strip()) if value else None

# Database Models
class User(db.Model):
    __tablename__ = 'inv_users'
    uid = db.Column(db.String(36), primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    domain = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Inventory(db.Model):
    __tablename__ = 'inventory'
    id = db.Column(db.Integer, primary_key=True)
    item_name = db.Column(db.String(100), nullable=False)
    serial_number = db.Column(db.String(100), unique=True)
    license_power_capacity = db.Column(db.String(100))
    item_type = db.Column(db.String(50), nullable=False)
    band = db.Column(db.String(50))
    frequency_range = db.Column(db.String(50))
    item_in_stock = db.Column(db.Integer, nullable=False, default=1)
    moved_to = db.Column(db.String(100))
    vendor = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    category = db.Column(db.String(50), nullable=False)
    moved_from = db.Column(db.String(100))
    created_by = db.Column(db.String(50), nullable=False)
    updated_by = db.Column(db.String(50), nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

class DRSLink(db.Model):
    __tablename__ = 'drs_links'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid4()))
    link_name = db.Column(db.String(100), nullable=False)
    site_name = db.Column(db.String(100))
    domain = db.Column(db.String(100))
    site_id = db.Column(db.String(100))
    site_lic = db.Column(db.String(100))
    site_type = db.Column(db.String(100))
    link_vendor = db.Column(db.String(100))
    tx_freq = db.Column(db.String(50))
    rx_freq = db.Column(db.String(50))
    tx_power = db.Column(db.String(50))
    mrmc_profile = db.Column(db.String(100))
    vlan_numbers = db.Column(db.Text)
    ports = db.Column(db.Text)
    e1_ports = db.Column(db.Text)
    link_ips = db.Column(db.Text)
    link_capacity = db.Column(db.String(100))
    link_license = db.Column(db.String(100))
    link_license_key = db.Column(db.String(100))
    idu_sn = db.Column(db.String(100))
    odu_sn = db.Column(db.String(100))
    dish_size = db.Column(db.String(50))
    tower_height = db.Column(db.String(50))
    dish_height = db.Column(db.String(50))
    remarks = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.String(50), nullable=False)
    updated_by = db.Column(db.String(50), nullable=False)

# Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST' and form.validate_on_submit():
        username = form.username.data.lower().strip()
        password = form.password.data.strip()

        try:
            user = User.query.filter_by(username=username).first()
            if not user:
                flash('Invalid username')
                return render_template('login.html', form=form)

            if not check_password_hash(user.password, password):
                flash('Invalid password')
                return render_template('login.html', form=form)

            session['user_id'] = str(user.uid)
            session['username'] = user.username
            session['domain'] = user.domain
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            logger.error(f"Login failed: {str(e)}")
            flash(f'Login failed: {str(e)}')
            return render_template('login.html', form=form)

    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    try:
        username = session.get('username', 'unknown_user')
        user_domain = session.get('domain', 'All')
        logger.debug(f"Dashboard accessed by {username} (Domain: {user_domain})")

        # Inventory stats with domain filter
        inventory_query = Inventory.query
        if user_domain != 'All':
            inventory_query = inventory_query.filter(Inventory.moved_to == user_domain)

        total_items = inventory_query.count()
        items_by_category = dict(
            inventory_query.with_entities(Inventory.category, db.func.count(Inventory.id))
            .group_by(Inventory.category).all()
        )
        items_by_type = dict(
            inventory_query.with_entities(Inventory.item_type, db.func.count(Inventory.id))
            .group_by(Inventory.item_type).all()
        )
        items_by_vendor = dict(
            inventory_query.with_entities(Inventory.vendor, db.func.count(Inventory.id))
            .group_by(Inventory.vendor).all()
        )

        # DRS Links stats with domain filter
        drs_query = DRSLink.query
        if user_domain != 'All':
            drs_query = drs_query.filter(DRSLink.domain == user_domain)

        total_links = drs_query.count()
        links_by_domain = dict(
            drs_query.with_entities(DRSLink.domain, db.func.count(DRSLink.id))
            .group_by(DRSLink.domain).all()
        )
        links_by_vendor = dict(
            drs_query.with_entities(DRSLink.link_vendor, db.func.count(DRSLink.id))
            .group_by(DRSLink.link_vendor).all()
        )

        # Recent entries with domain filter
        recent_items = inventory_query.order_by(Inventory.created_at.desc()).limit(5).all()
        recent_links = drs_query.order_by(DRSLink.created_at.desc()).limit(5).all()

        pkt_tz = pytz.timezone('Asia/Karachi')
        for item in recent_items:
            item.created_at_formatted = item.created_at.replace(tzinfo=pytz.UTC).astimezone(pkt_tz).strftime('%Y-%m-%d %H:%M:%S')
            item.updated_at_formatted = item.updated_at.replace(tzinfo=pytz.UTC).astimezone(pkt_tz).strftime('%Y-%m-%d %H:%M:%S')
        for link in recent_links:
            link.created_at_formatted = link.created_at.replace(tzinfo=pytz.UTC).astimezone(pkt_tz).strftime('%Y-%m-%d %H:%M:%S')
            link.updated_at_formatted = link.updated_at.replace(tzinfo=pytz.UTC).astimezone(pkt_tz).strftime('%Y-%m-%d %H:%M:%S')

        return render_template(
            'index.html',
            total_items=total_items,
            items_by_category=items_by_category,
            items_by_type=items_by_type,
            items_by_vendor=items_by_vendor,
            total_links=total_links,
            links_by_domain=links_by_domain,
            links_by_vendor=links_by_vendor,
            recent_items=recent_items,
            recent_links=recent_links,
            user_domain=user_domain
        )
    except Exception as e:
        logger.error(f"Error in index route: {str(e)}")
        flash(f"Error: {str(e)}")
        return redirect(url_for('index'))

@app.route('/add_inventory', methods=['GET', 'POST'])
@login_required
def add_inventory():
    try:
        username = session.get('username', 'unknown_user')
        user_domain = session.get('domain', 'All')
        form = AddInventoryForm()
        
        # Set domain choices based on user_domain
        if user_domain != 'All':
            form.domain.choices = [(user_domain, user_domain)]
        else:
            form.domain.choices = [('', 'Select Domain')] + [(dom, dom) for dom in VALID_DOMAINS]

        if request.method == 'POST' and form.validate_on_submit():
            item_name = sanitize_text(form.item_name.data)
            serial_number = sanitize_text(form.serial_number.data)
            license_power_capacity = sanitize_text(form.license_power_capacity.data)
            item_type = form.item_type.data
            other_item_type = sanitize_text(form.other_item_type.data)
            band = sanitize_text(form.band.data)
            frequency_range = sanitize_text(form.frequency_range.data)
            item_in_stock = form.item_in_stock.data or 1
            moved_to = sanitize_text(form.moved_to.data)
            vendor = sanitize_text(form.vendor.data)
            category = form.category.data
            moved_from = sanitize_text(form.moved_from.data)
            domain = form.domain.data if user_domain == 'All' else user_domain

            if not all([item_name, serial_number, item_type, category]):
                flash('Item name, serial number, item type, and category are required')
                return render_template('add_inventory.html', form=form, valid_categories=VALID_CATEGORIES, valid_item_types=VALID_ITEM_TYPES, user_domain=user_domain)

            if item_type == 'Other' and not other_item_type:
                flash('Please specify the item type for "Other"')
                return render_template('add_inventory.html', form=form, valid_categories=VALID_CATEGORIES, valid_item_types=VALID_ITEM_TYPES, user_domain=user_domain)

            if item_type not in VALID_ITEM_TYPES:
                flash('Invalid item type')
                return render_template('add_inventory.html', form=form, valid_categories=VALID_CATEGORIES, valid_item_types=VALID_ITEM_TYPES, user_domain=user_domain)

            if category not in VALID_CATEGORIES:
                flash('Invalid category')
                return render_template('add_inventory.html', form=form, valid_categories=VALID_CATEGORIES, valid_item_types=VALID_ITEM_TYPES, user_domain=user_domain)

            final_item_type = other_item_type if item_type == 'Other' else item_type

            inventory = Inventory(
                item_name=item_name,
                serial_number=serial_number,
                license_power_capacity=license_power_capacity,
                item_type=final_item_type,
                band=band,
                frequency_range=frequency_range,
                item_in_stock=item_in_stock,
                moved_to=moved_to,
                vendor=vendor,
                category=category,
                moved_from=moved_from,
                created_by=username,
                updated_by=username,
                updated_at=datetime.utcnow()
            )
            db.session.add(inventory)
            db.session.commit()
            flash('Inventory item added successfully!', 'success')
            return redirect(url_for('view_inventory'))
        return render_template('add_inventory.html', form=form, valid_categories=VALID_CATEGORIES, valid_item_types=VALID_ITEM_TYPES, user_domain=user_domain)
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error in add_inventory: {str(e)}")
        flash(f"Error adding inventory: {str(e)}")
        return render_template('add_inventory.html', form=form, valid_categories=VALID_CATEGORIES, valid_item_types=VALID_ITEM_TYPES, user_domain=user_domain)

@app.route('/view_inventory', methods=['GET'])
@login_required
def view_inventory():
    try:
        page = request.args.get('page', 1, type=int)
        search = request.args.get('search', '').strip()
        user_domain = session.get('domain', 'All')

        query = Inventory.query
        if user_domain != 'All':
            query = query.filter(Inventory.moved_to == user_domain)
        if search:
            query = query.filter(Inventory.serial_number.ilike(f'%{search}%'))

        per_page = 10
        pagination = query.order_by(Inventory.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)

        pkt_tz = pytz.timezone('Asia/Karachi')
        for item in pagination.items:
            item.created_at_formatted = item.created_at.replace(tzinfo=pytz.UTC).astimezone(pkt_tz).strftime('%Y-%m-%d %H:%M:%S')
            item.updated_at_formatted = item.updated_at.replace(tzinfo=pytz.UTC).astimezone(pkt_tz).strftime('%Y-%m-%d %H:%M:%S')

        return render_template(
            'view_inventory.html',
            items=pagination,
            search=search
        )
    except Exception as e:
        logger.error(f"Error in view_inventory: {str(e)}")
        flash(f"Error: {str(e)}")
        return redirect(url_for('index'))

@app.route('/add_drs_links', methods=['GET', 'POST'])
@login_required
def add_drs_links():
    try:
        username = session.get('username', 'unknown_user')
        user_domain = session.get('domain', 'All')
        form = AddDRSLinkForm()
        
        # Set domain choices based on user_domain
        if user_domain != 'All':
            form.domain.choices = [(user_domain, user_domain)]
        else:
            form.domain.choices = [('', 'Select Domain')] + [(dom, dom) for dom in VALID_DOMAINS]

        if request.method == 'POST' and form.validate_on_submit():
            link_name = sanitize_text(form.link_name.data)
            site_name = sanitize_text(form.site_name.data)
            domain = form.domain.data if user_domain == 'All' else user_domain
            site_id = sanitize_text(form.site_id.data)
            site_lic = sanitize_text(form.site_lic.data)
            site_type = sanitize_text(form.site_type.data)
            link_vendor = sanitize_text(form.link_vendor.data)
            tx_freq = sanitize_text(form.tx_freq.data)
            rx_freq = sanitize_text(form.rx_freq.data)
            tx_power = sanitize_text(form.tx_power.data)
            mrmc_profile = sanitize_text(form.mrmc_profile.data)
            vlan_numbers = sanitize_text(form.vlan_numbers.data)
            ports = sanitize_text(form.ports.data)
            e1_ports = sanitize_text(form.e1_ports.data)
            link_ips = sanitize_text(form.link_ips.data)
            link_capacity = sanitize_text(form.link_capacity.data)
            link_license = sanitize_text(form.link_license.data)
            link_license_key = sanitize_text(form.link_license_key.data)
            idu_sn = sanitize_text(form.idu_sn.data)
            odu_sn = sanitize_text(form.odu_sn.data)
            dish_size = sanitize_text(form.dish_size.data)
            tower_height = sanitize_text(form.tower_height.data)
            dish_height = sanitize_text(form.dish_height.data)
            remarks = sanitize_text(form.remarks.data)

            if not link_name:
                flash('Link name is required')
                return render_template('add_drs_links.html', form=form, user_domain=user_domain)

            drs_link = DRSLink(
                link_name=link_name,
                site_name=site_name,
                domain=domain,
                site_id=site_id,
                site_lic=site_lic,
                site_type=site_type,
                link_vendor=link_vendor,
                tx_freq=tx_freq,
                rx_freq=rx_freq,
                tx_power=tx_power,
                mrmc_profile=mrmc_profile,
                vlan_numbers=vlan_numbers,
                ports=ports,
                e1_ports=e1_ports,
                link_ips=link_ips,
                link_capacity=link_capacity,
                link_license=link_license,
                link_license_key=link_license_key,
                idu_sn=idu_sn,
                odu_sn=odu_sn,
                dish_size=dish_size,
                tower_height=tower_height,
                dish_height=dish_height,
                remarks=remarks,
                created_by=username,
                updated_by=username,
                updated_at=datetime.utcnow()
            )
            db.session.add(drs_link)
            db.session.commit()
            flash('DRS Link added successfully!', 'success')
            return redirect(url_for('view_drs_links'))
        return render_template('add_drs_links.html', form=form, user_domain=user_domain)
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error in add_drs_links: {str(e)}")
        flash(f"Error adding DRS link: {str(e)}")
        return render_template('add_drs_links.html', form=form, user_domain=user_domain)

@app.route('/view_drs_links', methods=['GET'])
@login_required
def view_drs_links():
    try:
        page = request.args.get('page', 1, type=int)
        search = request.args.get('search', '').strip()
        user_domain = session.get('domain', 'All')

        query = DRSLink.query
        if user_domain != 'All':
            query = query.filter(DRSLink.domain == user_domain)
        if search:
            query = query.filter(DRSLink.link_name.ilike(f'%{search}%'))

        per_page = 10
        pagination = query.order_by(DRSLink.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)

        pkt_tz = pytz.timezone('Asia/Karachi')
        for link in pagination.items:
            link.created_at_formatted = link.created_at.replace(tzinfo=pytz.UTC).astimezone(pkt_tz).strftime('%Y-%m-%d %H:%M:%S')
            link.updated_at_formatted = link.updated_at.replace(tzinfo=pytz.UTC).astimezone(pkt_tz).strftime('%Y-%m-%d %H:%M:%S')

        return render_template(
            'view_drs_links.html',
            links=pagination,
            search=search
        )
    except Exception as e:
        logger.error(f"Error in view_drs_links: {str(e)}")
        flash(f"Error: {str(e)}")
        return redirect(url_for('index'))

@app.route('/export_inventory', methods=['GET'])
@login_required
def export_inventory():
    try:
        search = request.args.get('search', '').strip()
        user_domain = session.get('domain', 'All')

        query = Inventory.query
        if user_domain != 'All':
            query = query.filter(Inventory.moved_to == user_domain)
        if search:
            query = query.filter(Inventory.serial_number.ilike(f'%{search}%'))

        data = query.order_by(Inventory.created_at.desc()).all()
        pkt_tz = pytz.timezone('Asia/Karachi')
        records = []
        for item in data:
            records.append({
                'ID': item.id,
                'Item Name': item.item_name,
                'Serial Number': item.serial_number or '-',
                'License/Power Capacity': item.license_power_capacity or '-',
                'Item Type': item.item_type or '-',
                'Band': item.band or '-',
                'Frequency Range': item.frequency_range or '-',
                'Item in Stock': item.item_in_stock,
                'Moved To': item.moved_to or '-',
                'Vendor': item.vendor or '-',
                'Category': item.category or '-',
                'Moved From': item.moved_from or '-',
                'Created By': item.created_by,
                'Created At': item.created_at.replace(tzinfo=pytz.UTC).astimezone(pkt_tz).strftime('%Y-%m-%d %H:%M:%S'),
                'Updated By': item.updated_by,
                'Updated At': item.updated_at.replace(tzinfo=pytz.UTC).astimezone(pkt_tz).strftime('%Y-%m-%d %H:%M:%S')
            })

        df = pd.DataFrame(records)
        output = BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='Inventory Data')
        output.seek(0)

        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name='inventory_data.xlsx'
        )
    except Exception as e:
        logger.error(f"Error in export_inventory: {str(e)}")
        flash(f"Error exporting data: {str(e)}")
        return redirect(url_for('view_inventory'))

@app.route('/export_drs_links', methods=['GET'])
@login_required
def export_drs_links():
    try:
        search = request.args.get('search', '').strip()
        user_domain = session.get('domain', 'All')

        query = DRSLink.query
        if user_domain != 'All':
            query = query.filter(DRSLink.domain == user_domain)
        if search:
            query = query.filter(DRSLink.link_name.ilike(f'%{search}%'))

        data = query.order_by(DRSLink.created_at.desc()).all()
        pkt_tz = pytz.timezone('Asia/Karachi')
        records = []
        for link in data:
            records.append({
                'ID': link.id,
                'Link Name': link.link_name,
                'Site Name': link.site_name or '-',
                'Domain': link.domain or '-',
                'Site ID': link.site_id or '-',
                'Site License': link.site_lic or '-',
                'Site Type': link.site_type or '-',
                'Link Vendor': link.link_vendor or '-',
                'TX Frequency': link.tx_freq or '-',
                'RX Frequency': link.rx_freq or '-',
                'TX Power': link.tx_power or '-',
                'MRMC Profile': link.mrmc_profile or '-',
                'VLAN Numbers': link.vlan_numbers or '-',
                'Ports': link.ports or '-',
                'E1 Ports': link.e1_ports or '-',
                'Link IPs': link.link_ips or '-',
                'Link Capacity': link.link_capacity or '-',
                'Link License': link.link_license or '-',
                'Link License Key': link.link_license_key or '-',
                'IDU Serial Number': link.idu_sn or '-',
                'ODU Serial Number': link.odu_sn or '-',
                'Dish Size': link.dish_size or '-',
                'Tower Height': link.tower_height or '-',
                'Dish Height': link.dish_height or '-',
                'Remarks': link.remarks or '-',
                'Created By': link.created_by,
                'Created At': link.created_at.replace(tzinfo=pytz.UTC).astimezone(pkt_tz).strftime('%Y-%m-%d %H:%M:%S'),
                'Updated By': link.updated_by,
                'Updated At': link.updated_at.replace(tzinfo=pytz.UTC).astimezone(pkt_tz).strftime('%Y-%m-%d %H:%M:%S')
            })

        df = pd.DataFrame(records)
        output = BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='DRS Links Data')
        output.seek(0)

        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name='drs_links_data.xlsx'
        )
    except Exception as e:
        logger.error(f"Error in export_drs_links: {str(e)}")
        flash(f"Error exporting data: {str(e)}")
        return redirect(url_for('view_drs_links'))

if __name__ == '__main__':
    app.run(debug=True)