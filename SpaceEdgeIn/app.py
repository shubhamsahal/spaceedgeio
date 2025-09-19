import os
import json
import io
import stripe
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, jsonify, abort
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename
from flask_discord import DiscordOAuth2Session
from azure.storage.blob import BlobServiceClient, ContentSettings
import random
import smtplib
from email.mime.text import MIMEText
from pymongo import MongoClient
import mimetypes

# Set the templates and static folders relative to the main app folder.
# This assumes your directory structure is `.../SpaceEdgeIn/app.py`
# and the templates and static folders are inside a subfolder.
base_dir = os.path.dirname(os.path.abspath(__file__))
template_dir = os.path.join(base_dir, 'templates')
static_dir = os.path.join(base_dir, 'static')


# Create the Flask app, pointing to the templates and static folders
app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)

# Local dev only: allow OAuth2 over HTTP
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"


# Azure Blob Storage connection
AZURE_CONNECTION_STRING = "DefaultEndpointsProtocol=https;AccountName=userfilesedge;AccountKey=8Hp4bJe7Ee6Sg+mT/WMh342Tobqd9GO/Np6tnk+MyMMD304A7e2mM+lLikIvvyic0IVCmRhHj1sA+ASthZC6lg==;EndpointSuffix=core.windows.net"
CONTAINER_NAME = "userfilesedge"

blob_service_client = None
container_client = None
try:
    blob_service_client = BlobServiceClient.from_connection_string(AZURE_CONNECTION_STRING)
    # This will create the container if it doesn't exist, and do nothing if it does.
    container_client = blob_service_client.get_container_client(CONTAINER_NAME)
    container_client.create_container(exists_ok=True)
    print("Successfully connected to Azure Blob Storage.")
except Exception as e:
    print(f"Error connecting to Azure Blob Storage: {e}")
    # You might want to halt the application or use a fallback here in a real app


# Cosmos DB Mongo connection string
COSMOS_CONNECTION_STRING = "mongodb://spaceedgebd:bS1lHn2KVfTdDk9YCYfwUiWIYvKepsQqdY82XtL9kPWkYh2wPCblk3DxSqbhvPovyHVX1OQ5TSubACDb6zjlGg==@spaceedgebd.mongo.cosmos.azure.com:10255/?ssl=true&replicaSet=globaldb&retrywrites=false&maxIdleTimeMS=120000&appName=@spaceedgebd@"

client = None
db = None
users = None
try:
    client = MongoClient(COSMOS_CONNECTION_STRING)
    db = client["spaceedge"]
    users = db["users"]
    print("Successfully connected to Cosmos DB.")
except Exception as e:
    print(f"Error connecting to Cosmos DB: {e}")
    # You might want to halt the application or use a fallback here in a real app


# Flask config
app.config['SECRET_KEY'] = '309d0aed19d3e49c754f974d8827b32bd1ab0351894fea1901557f8a47e64183'

# Discord OAuth2
app.config["DISCORD_CLIENT_ID"] = "1410341983284760776"
app.config["DISCORD_CLIENT_SECRET"] = "JJwIjGOJhiOcBRWxAHMR8lcl1cvEmH0W"
app.config["DISCORD_REDIRECT_URI"] = "https://spaceedgein.onrender.com/discord/callback"

# Always build the URL dynamically from config
AUTHORIZATION_BASE_URL = (
    f"https://discord.com/oauth2/authorize"
    f"?client_id={app.config['DISCORD_CLIENT_ID']}"
    f"&response_type=code"
    f"&redirect_uri={app.config['DISCORD_REDIRECT_URI']}"
    f"&scope=identify+email"
)


# Init session
discord = DiscordOAuth2Session(app)


# Email OTP (Gmail SMTP)
def send_otp_email(email):
    otp = str(random.randint(100000, 999999))
    msg = MIMEText(f"Your OTP for Space Edge is: {otp}")
    msg['Subject'] = "Your Space Edge OTP"
    msg['From'] = "noreplyverifyspaceedge@gmail.com"
    msg['To'] = email

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login('noreplyverifyspaceedge@gmail.com', 'jgkz knoi wqay ymqr')
    server.sendmail('noreplyverifyspaceedge@gmail.com', [email], msg.as_string())
    server.quit()

    return otp

bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg", "gif", "doc", "docx", "psd", "avi", "mov","mp3","zip","doc","xls","msi","exe","html"}

# Mapping of file extensions to icon filenames stored in your static/icons/ folder
EXT_ICONS = {
    "pdf": "pdf-icon.png",
    "png": "png-icon.png",
    "jpg": "jpg-icon.png",
    "jpeg": "jpeg-icon.png",
    "gif": "gif-icon.png",
    "doc": "doc-icon.png",
    "docx": "docx-icon.png",
    "psd": "psd-icon.png",
    "avi": "avi-icon.png",
    "mov": "mov-icon.png",
    "mp3": "mp3-icon.png",
    "zip": "zip-icon.png",
    "xls": "excel-icon.png",
    "msi": "msi-icon.png",
    "exe": "exe-icon.png",
    "html": "html-icon.png",
    "txt": "txt-icon.png",
    "css": "css-icon.png",
    "apk": "apk-icon.png",
    "py" : "py-icon.png",
}


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# Cosmos DB-based user model
class User(UserMixin):
    def __init__(self, id_, email, name, password_hash, plan_type='free', used_storage_gb=0.0):
        self.id = id_
        self.email = email
        self.name = name
        self.password_hash = password_hash
        self.plan_type = plan_type
        self.used_storage_gb = used_storage_gb
    
    def get_id(self):
        return str(self.id)

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

def load_user_from_db(user_id):
    if users is None:
        return None
    doc = users.find_one({'_id': user_id})
    if doc:
        return User(
            doc['_id'],
            doc['email'],
            doc['name'],
            doc.get('password_hash', ''),
            doc.get('plan_type', 'free'),
            doc.get('used_storage_gb', 0.0)
        )
    return None

def find_user_by_email(email):
    if users is None:
        return None
    doc = users.find_one({'email': email})
    if doc:
        return User(doc['_id'], doc['email'], doc['name'], doc.get('password_hash', ''))
    return None

def add_user_to_db(user_id, email, name, password_hash):
    if users is None:
        return
    users.insert_one({
        '_id': user_id,
        'email': email,
        'name': name,
        'password_hash': password_hash,
        'plan_type': 'free',
        'used_storage_gb': 0.0,
        'stripe_customer_id': None,
        'stripe_subscription_id': None
    })

@login_manager.user_loader
def load_user(user_id):
    return load_user_from_db(user_id)

# Azure helper functions for file storage
def azure_blob_key(user_email: str, filename: str) -> str:
    return f"{user_email}/{filename}"

def azure_upload(user_email: str, filename: str, fileobj) -> None:
    if container_client is None:
        print("Warning: Azure container client not available.")
        return
    blob_client = container_client.get_blob_client(azure_blob_key(user_email, filename))
    blob_client.upload_blob(fileobj, overwrite=True)

def azure_list(user_email: str):
    if container_client is None:
        print("Warning: Azure container client not available.")
        return []
    prefix = f"{user_email}/"
    blobs = container_client.list_blobs(name_starts_with=prefix)
    files = []
    for b in blobs:
        parts = b.name.split("/", 1)
        files.append(parts[1] if len(parts) > 1 else b.name)
    return files

def azure_download(user_email: str, filename: str) -> bytes:
    if container_client is None:
        print("Warning: Azure container client not available.")
        return b''
    blob_client = container_client.get_blob_client(azure_blob_key(user_email, filename))
    stream = blob_client.download_blob()
    return stream.readall()

def azure_delete(user_email: str, filename: str) -> None:
    if container_client is None:
        print("Warning: Azure container client not available.")
        return
    blob_client = container_client.get_blob_client(azure_blob_key(user_email, filename))
    blob_client.delete_blob()

# Routes
@app.route("/")
def home():
    # If the user is logged in, redirect to dashboard
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    # Otherwise, show a real homepage with login & signup links
    return render_template("home.html")


@app.route("/discord/login")
def discord_login():
    return discord.create_session()

@app.route("/discord/callback")
def discord_callback():
    try:
        discord.callback()
    except Exception as e:
        print(f"Error in discord.callback(): {e}")
        flash("OAuth callback error. See server log.", "error")
        return redirect(url_for("login"))
    
    user = discord.fetch_user()
    user_id = str(user.id)

    # Check if user exists in Cosmos DB
    if not load_user_from_db(user_id):
        new_user = User(
            id_=user_id,
            email=f"{user_id}@discord",
            name=user.name,
            password_hash=""
        )
        add_user_to_db(user_id, new_user.email, user.name, "")

    login_user(load_user_from_db(user_id))
    session["discord_username"] = user.name
    flash(f"Logged in as Discord user: {user.name}", "success")
    return redirect(url_for("dashboard"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        action = request.form.get("action")
        email = request.form.get("email")

        if action == "send_otp":
            if find_user_by_email(email):
                flash("This account is already registered. Please login instead.", "error")
                return redirect(url_for("login"))

            otp = send_otp_email(email)
            if otp:
                session["otp"] = otp
                session["email"] = email
                flash("OTP sent to your email!", "info")
                return render_template("register.html", otp_sent=True, email=email)
            else:
                flash("Error sending OTP. Try again.", "error")

        elif action == "verify_otp":
            entered_otp = str(request.form.get("otp", "")).strip()
            saved_otp = str(session.get("otp", "")).strip()

            if entered_otp == saved_otp:
                flash("OTP verified! Now set your name & password.", "success")
                return render_template("register.html", otp_verified=True, email=session.get("email"))
            else:
                flash("Invalid OTP. Try again.", "error")
                return render_template("register.html", otp_sent=True, email=session.get("email"))

        elif action == "set_password":
            name = request.form.get("name")
            password = request.form.get("password")
            email = session.get("email")

            if not email:
                flash("Session expired. Please start again.", "error")
                return redirect(url_for("register"))

            if not name:
                flash("Please enter your name.", "error")
                return render_template("register.html", otp_verified=True, email=email)

            password_hash = bcrypt.generate_password_hash(password).decode("utf-8")
            user_id = email.lower()

            add_user_to_db(user_id, email, name, password_hash)

            flash("Registration successful! You can now login.", "success")
            session.pop("otp", None)
            session.pop("email", None)
            return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    email = None
    if request.method == "POST":
        email = request.form.get("email", "").lower()
        password = request.form.get("password", "")
        user = find_user_by_email(email)
        if user and user.check_password(password):
            login_user(user)
            flash("Successfully logged in.", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid email or password", "error")

    if 'discord_username' in session and not current_user.is_authenticated:
        flash(f"Logged in as Discord user: {session.get('discord_username')}", "info")

    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.pop("discord_username", None)
    session.pop('_flashes', None)
    return redirect(url_for("login"))

# Add this to the top of your file
STORAGE_LIMITS_GB = {
    'free': 15.0,
    'pro': 500.0
}

@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    user_doc = users.find_one({'_id': current_user.get_id()})
    user_plan = user_doc.get('plan_type', 'free')
    used_storage_gb = user_doc.get('used_storage_gb', 0.0)
    max_storage_gb = STORAGE_LIMITS_GB.get(user_plan, 15.0)

    if request.method == "POST":
        if "file" not in request.files:
            flash("No file part", "warning")
        else:
            file = request.files["file"]
            if file.filename == "":
                flash("No selected file", "warning")
            elif not allowed_file(file.filename):
                flash("File type not allowed", "warning")
            else:
                file.seek(0, 2)
                file_size_bytes = file.tell()
                file.seek(0)
                file_size_gb = file_size_bytes / (1024 ** 3)
                if (used_storage_gb + file_size_gb) > max_storage_gb:
                    flash(f"Storage limit exceeded. You have used {used_storage_gb:.2f} GB of your {max_storage_gb} GB limit.", "warning")
                else:
                    filename = secure_filename(file.filename)
                    azure_upload(current_user.email, filename, file)
                    users.update_one(
                        {'_id': current_user.get_id()},
                        {'$inc': {'used_storage_gb': file_size_gb}}
                    )
                    flash(f"File {filename} uploaded successfully!", "success")

                    # Redirect after POST to avoid form resubmission warning
                    return redirect(url_for("dashboard"))

    files_raw = azure_list(current_user.email)
    files = []
    for f in files_raw:
        url = f"https://userfilesedge.blob.core.windows.net/userfilesedge/{current_user.email}/{f}"
        files.append({"filename": f, "public_url": url})

    return render_template(
        "upload.html",
        files=files,
        user=current_user.name,
        current_user_email=current_user.email,
        used_storage_gb=used_storage_gb,
        max_storage_gb=max_storage_gb,
        ext_icons=EXT_ICONS
    )


@app.route("/share/<user_email>/<filename>")
def share_file_page(user_email, filename):
    public_url = f"https://userfilesedge.blob.core.windows.net/userfilesedge/{user_email}/{filename}"
    file_ext = filename.rsplit('.', 1)[-1].lower()
    return render_template(
        "public_file.html",
        filename=filename,
        user_email=user_email,
        public_url=public_url,
        file_ext=file_ext
    )


@app.route("/files/<user_email>/<filename>")
def public_download(user_email, filename):
    try:
        data = azure_download(user_email, filename)
        mime_type = mimetypes.guess_type(filename) or 'application/octet-stream'
        return send_file(
            io.BytesIO(data),
            download_name=filename,
            mimetype=mime_type,
            as_attachment=True
        )
    except Exception:
        abort(404)


@app.route("/files/<user_email>/<filename>/download")
def public_file_download(user_email, filename):
    try:
        public_url = f"https://userfilesedge.blob.core.windows.net/userfilesedge/{user_email}/{filename}"
        return redirect(public_url)
    except Exception:
        abort(404)


@app.route("/files/<user_email>/<filename>/thumb")
def file_thumbnail(user_email, filename):
    # For images only, serve a thumbnail (or full image if thumbnailing not yet implemented)
    data = azure_download(user_email, filename)
    mime_type = mimetypes.guess_type(filename)[0] or 'image/png'
    return send_file(
        io.BytesIO(data),
        download_name=filename,
        mimetype=mime_type
    )


@app.route("/uploads/<path:filename>")
@login_required
def uploaded_file(filename):
    try:
        data = azure_download(current_user.email, filename)
        return send_file(
            io.BytesIO(data),
            download_name=filename,
            as_attachment=True
        )
    except Exception as e:
        print("Download error:", e)
        flash("File not found or you don't have access.", "error")
        return redirect(url_for("dashboard"))

@app.route("/delete/<path:filename>", methods=["POST"])
@login_required
def delete_file(filename):
    try:
        blob_client = container_client.get_blob_client(azure_blob_key(current_user.email, filename))
        blob_properties = blob_client.get_blob_properties()
        file_size_gb = blob_properties.size / (1024 ** 3)
        
        azure_delete(current_user.email, filename)
        
        # Decrement used storage
        users.update_one(
            {'_id': current_user.get_id()},
            {'$inc': {'used_storage_gb': -file_size_gb}}
        )
        
        flash(f"File {filename} deleted successfully.", "success")
    except Exception as e:
        flash(f"Error deleting file: {e}", "error")
        
    return redirect(url_for("dashboard"))

@app.route("/pricing")
def pricing():
    return render_template("pricing.html")

@app.route("/create-checkout-session", methods=['POST'])
def create_checkout_session():
    try:
        checkout_session = stripe.checkout.Session.create(
            line_items=[
                {
#                 'price': PRO_PLAN_PRICE_ID,
                    'quantity': 1,
                },
            ],
            mode='subscription',
            success_url=url_for('success', _external=True) + '?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=url_for('pricing', _external=True),
        )
        return jsonify({'id': checkout_session.id})
    except Exception as e:
        return jsonify(error=str(e)), 403

@app.route("/success")
@login_required
def success():
    # User will be redirected here after a successful Stripe payment.
    # The actual subscription update will happen via webhook.
    return "<h1>Payment successful! We'll update your account shortly.</h1>"
    
@app.route("/cancel")
@login_required
def cancel():
    # User will be redirected here if they cancel Stripe Checkout.
    flash("Payment cancelled. You can try again at any time.", "info")
    return redirect(url_for("pricing"))


@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(e):
    message = "Sorry, file is too large!"
    message_class = "warning-message"
    try:
        files = azure_list(current_user.email)
        user = current_user.name
    except Exception:
        files = []
        user = ""
    return (
        render_template(
            "upload.html", message=message, message_class=message_class, files=files, user=user
        ),
        413,
    )

if __name__ == "__main__":
    app.run(debug=True)
"
