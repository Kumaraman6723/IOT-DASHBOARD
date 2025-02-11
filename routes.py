from functools import wraps
from flask import Flask, make_response, render_template, request, redirect, url_for, session, flash, jsonify
import pymysql
from models import fetch_email, fetch_email_from_user, recover_passkey, fetch_users, get_db_connection
from email_service import send_email
from forms import AddDeviceForm, RegisterForm, RequestDeviceForm, UpdateProfileForm, VerificationForm, OTPForm, ForgetPass
from utils import otpmaker, check_password
from config import appConf, SITE_KEY, SECRET_KEY
from werkzeug.security import generate_password_hash
from authlib.integrations.flask_client import OAuth
from authlib.integrations.base_client import OAuthError
import requests
import json
import time
from datetime import datetime, timedelta
import uuid
import logging
import random
import string
from werkzeug.security import generate_password_hash
import secrets
import requests
from datetime import datetime
import pytz
# Configure logging
logging.basicConfig(level=logging.DEBUG)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash("You need to be logged in to access this page.", "error")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

def register_routes(app, oauth):
    # Login route
      # Login route
    @app.route("/", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            store = fetch_users()
            token = request.form.get('cf-turnstile-response')
            ip = request.remote_addr

            # Verify Cloudflare Turnstile
            form_data = {
                'secret': SECRET_KEY,
                'response': token,
                'remoteip': ip
            }
            response = requests.post('https://challenges.cloudflare.com/turnstile/v0/siteverify', data=form_data)
            outcome = response.json()

        #   if not outcome['success']:
        #        flash('The provided Turnstile token was not valid!', 'error')
        #        return redirect(url_for('login'))

            email = request.form["user"]
            password = request.form["password"]

            # Check if it's the admin login
            admin_email = "aman22csu266@ncuindia.edu"
            admin_id = "admin12324"
            admin_password = "Jadoo@12"
            if email == admin_id or email == admin_email:
                if password == admin_password:
                    session["user"] = {"email": admin_email}
                    session["login_email"] = admin_email
                    log_action(admin_email, "Admin logged in")
                    return redirect(url_for('admindashboard'))
                else:
                    flash("Invalid admin email or password", "error")
            else:
                user = next((x for x in store if x[0] == email or x[2] == email), None)

                if user and check_password(user[1], password):
                    mail_fetch = fetch_email_from_user(email)
                    print(mail_fetch)
                    if mail_fetch is not None:
                        print(mail_fetch)
                        session["user"] = {"email": mail_fetch}
                        session["login_email"] = mail_fetch
                        log_action(email, "User logged in")
                        return redirect(url_for('two_step'))
                    else:
                        session["user"] = {"email": email}
                        session["login_email"] = email
                        log_action(email, "User logged in")
                        return redirect(url_for('two_step'))
                else:
                    flash("Invalid email or password", "error")

        return render_template("login.html", site_key=SITE_KEY)
    #admindashboard route
    @app.route("/admindashboard")
    @login_required
    def admindashboard():
    # You can add logic here to display relevant admin data
     return render_template("Admindashboard.html")
    # Home route
    @app.route("/home")
    @login_required
    def home():
        return render_template("home.html", session=session.get("user"),
                               pretty=json.dumps(session.get("user"), indent=4))
        
    def generate_hashed_password():
     random_password = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=12))
     hashed_password = generate_password_hash(random_password, method='pbkdf2:sha256', salt_length=8)
     return hashed_password, random_password

    def generate_username():
     while True:
        username = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT username FROM user_profiles WHERE username=%s", (username,))
        existing_username = cur.fetchone()
        conn.close()
        if not existing_username:
            return username

    @app.route("/signin-google")
    def googleCallback():
     try:
        token = oauth.myApp.authorize_access_token()
     except OAuthError:
        return redirect(url_for("login"))

    # Fetch user info and person data
     user_info_response = requests.get(
        f'https://www.googleapis.com/oauth2/v1/userinfo?access_token={token["access_token"]}',
        headers={'Authorization': f'Bearer {token["access_token"]}'}
     )
     user_info = user_info_response.json()

     person_data_response = requests.get(
        "https://people.googleapis.com/v1/people/me?personFields=genders,birthdays",
        headers={"Authorization": f"Bearer {token['access_token']}"}
     )
     person_data = person_data_response.json()

     token["user_info"] = user_info
     token["person_data"] = person_data
     session["user"] = token

    # Extract additional data
     email = user_info["email"]
     first_name = user_info.get("given_name", "")
     last_name = user_info.get("family_name", "")
     profile_id = str(uuid.uuid4())

    # Generate random username and hashed password
     username = generate_username()
     hashed_password, _ = generate_hashed_password()

    # Extract birthday and gender
     birthday = None
     gender = None

     if "birthdays" in person_data and person_data["birthdays"]:
        birthday_data = person_data["birthdays"][0].get("date")
        if birthday_data:
            birthday = f"{birthday_data.get('year', '0000')}-{birthday_data.get('month', '00')}-{birthday_data.get('day', '00')}"

     if "genders" in person_data and person_data["genders"]:
        gender = person_data["genders"][0].get("value")

     conn = get_db_connection()
     cur = conn.cursor()
     cur.execute("SELECT * FROM user_profiles WHERE email=%s", (email,))
     existing_user = cur.fetchone()

    # Convert UTC timestamps to IST
     utc_now = datetime.now()
     ist_now = utc_now.astimezone(pytz.timezone('Asia/Kolkata'))

     if existing_user:
        # Use the existing contact if it exists
        existing_contact = existing_user[7]  # Assuming contact is the 7th field in the user_profiles table
        if all(value is not None for value in existing_user):
            conn.close()
            session["login_email"] = email  # Save email to session
            log_action(email, "User logged in with Google")
            send_webhook("profile_updated", {"email": email, "action": "User logged in with Google"})
            return redirect(url_for("DashBoard"))

        logging.debug(f"Updating user with values: {first_name} {last_name}, {birthday}, {gender}, {existing_contact}, {email}")
        cur.execute(
            "UPDATE user_profiles SET name=%s, birthday=%s, gender=%s, contact=%s, updated_at=%s WHERE email=%s",
            (f"{first_name} {last_name}", birthday, gender, existing_contact, ist_now, email)
        )
        send_webhook("profile_updated", {"email": email, "action": "User logged in with Google"})
     else:
        # Insert a new user with contact set to None
        logging.debug(f"Inserting user with values: {email}, {username}, {hashed_password}, {first_name} {last_name}, {birthday}, {gender}, None, {profile_id}")
        cur.execute(
            "INSERT INTO user_profiles (email, username, password, name, birthday, gender, contact, profile_id, created_at, updated_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (email, username, hashed_password, f"{first_name} {last_name}", birthday, gender, None, profile_id, ist_now, ist_now)
        )
        send_webhook("profile_created", {"email": email, "action": "User registered with Google"})

     conn.commit()
     conn.close()

    # Save email in the session
     session["login_email"] = email
     session["user_email"] = email  # Save user_info.email to session
     log_action(email, "User logged in")
     return redirect(url_for("profile"))



    @app.route("/google-login")
    def googleLogin():
        session.clear()
        redirect_uri = url_for("googleCallback", _external=True)
        return oauth.myApp.authorize_redirect(redirect_uri=redirect_uri)
    # Logout route
    @app.route("/logout")
    def logout():
     email = session.get("login_email") or session.get("user", {}).get("user_info", {}).get("email")
     if "user" in session:
        token = session["user"].get("access_token")
        if token:
            requests.post("https://accounts.google.com/o/oauth2/revoke", params={"token": token})
     log_action(email, "User logged out")
     session.clear()
     return redirect(url_for("login"))

   
    @app.route("/register", methods=["GET", "POST"])
    def register():
        form = RegisterForm()
        if form.validate_on_submit():
            username = form.username.data
            email = form.email.data
            hash_and_salted_password = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8)
            
            conn = get_db_connection()
            cur = conn.cursor()
            
            # Check if the username is already taken
            cur.execute("SELECT COUNT(*) FROM user_profiles WHERE username = %s", (username,))
            if cur.fetchone()[0] > 0:
                flash("This username is already taken. Please choose a different one.", "danger")
                conn.close()
                return render_template("register.html", form=form)
            
            # Check if the email is already registered
            cur.execute("SELECT COUNT(*) FROM user_profiles WHERE email = %s", (email,))
            if cur.fetchone()[0] > 0:
                flash("This email is already registered. Please use a different email.", "danger")
                conn.close()
                return render_template("register.html", form=form)
            
            profile_id = str(uuid.uuid4())
            session.update({
                "username": username,
                "first_name": form.first_name.data,
                "last_name": form.last_name.data,
                "email": email,
                "password": hash_and_salted_password,
                "contact": form.contact.data,
                "profile_id": profile_id
            })
            
            log_action(email, "User registered")
            send_webhook("profile_created", {
            "email": email,
            "username": username,
            "first_name": form.first_name.data,
            "last_name": form.last_name.data,
            "contact": form.contact.data
             })
            return redirect(url_for("mail_otp"))
        
        return render_template("register.html", form=form)


    # Password verification route
    @app.route("/verification", methods=["GET", "POST"])
    def verify_pass():
        form = VerificationForm()
        if form.validate_on_submit():
            email = form.email.data
            if email in fetch_email():
                session["verify_email"] = email
                return redirect(url_for('two_step_forget'))
            flash("This email is not registered.", "danger")
        return render_template("verify_pass.html", form=form)

    # Dashboard route
    @app.route("/dashboard", methods=["GET", "POST"])
    @login_required
    def DashBoard():
        return render_template("DashBoard.html")

    # Contact route
    @app.route("/contact", methods=["GET", "POST"])
    def contact():
        if request.method == "POST":
            data = request.form
            send_email(data["email"], f"Name: {data['name']}\nPhone: {data['phone']}\nMessage: {data['message']}", "New Message")
            return render_template("contact.html", msg_sent=True)
        return render_template("contact.html", msg_sent=False)

    # Helper functions
    def is_otp_expired():
        expiry_time = session.get('OTP_EXPIRY')
        if isinstance(expiry_time, (int, float)):
            return time.time() > expiry_time
        elif isinstance(expiry_time, str):
            try:
                expiry_datetime = datetime.fromisoformat(expiry_time)
                return datetime.now() > expiry_datetime
            except ValueError:
                return True
        return True

    def send_new_otp(email, subject="New Message"):
        otp = otpmaker()
        send_email(email, f"OTP: {otp}", subject)
        session["otp"] = otp
        session['OTP_EXPIRY'] = time.time() + 30

    # Two-step verification routes
    @app.route("/two-step", methods=["GET", "POST"])
    def two_step():
        form = OTPForm()
        email = session.get("login_email")

        if request.method == "GET" or (request.method == "POST" and 'resend_otp' in request.form):
            if not session.get('OTP_SENT', False) or is_otp_expired() or 'resend_otp' in request.form:
                send_new_otp(email, "Email Verification")
                session['OTP_SENT'] = True
                if request.method == "POST":
                    return "", 204  # Return empty response for AJAX request

        if request.method == "POST" and 'resend_otp' not in request.form:
            otp_input = request.form["otp"]
            if is_otp_expired():
                flash("OTP has expired. Try again", "danger")
                return redirect(url_for("login"))
            elif otp_input == session.get("otp"):
                session.pop("otp", None)
                session.pop("OTP_EXPIRY", None)
                session.pop("OTP_SENT", None)
                session["user"] = {"email": email}  # Add any other user data as needed
                return redirect(url_for("profile"))
            else:
                flash("Incorrect OTP", "danger")

        return render_template("2FA.html", form=form)


    @app.route("/two-step-forget", methods=["GET", "POST"])
    def two_step_forget():
        form = OTPForm()
        email = session.get("verify_email")

        if request.method == "GET" or (request.method == "POST" and 'resend_otp' in request.form):
            if not session.get('OTP_SENT', False) or is_otp_expired() or 'resend_otp' in request.form:
                send_new_otp(email)
                session['OTP_SENT'] = True
                if request.method == "POST":
                    return "", 204  # Return empty response for AJAX request

        if request.method == "POST" and 'resend_otp' not in request.form:
            otp_input = request.form["otp"]
            if is_otp_expired():
                flash("OTP has expired. Try again", "danger")
                return redirect(url_for("verify_pass"))
            elif otp_input == session.get("otp"):
                session['forget_password_verified'] = True
                return redirect(url_for("forgot_pass"))
            else:
                flash("Incorrect OTP", "danger")

        return render_template("forgot_otp.html", form=form)

    # Forgot password route
    @app.route("/forgot", methods=["GET", "POST"])
    def forgot_pass():
        if not session.get('forget_password_verified'):
            flash("Please verify your email first.", "danger")
            return redirect(url_for('verify_pass'))

        form = ForgetPass()
        email = session.get("verify_email")
        
        if request.method == "POST" and form.validate_on_submit():
            hash_and_salted_password = generate_password_hash(
                form.password.data, method='pbkdf2:sha256', salt_length=8
            )
            recover_passkey(hash_and_salted_password, email)
            session.pop("verify_email")
            session.pop("forget_password_verified")
            flash("Password reset successful. Please log in.", "success")
            return redirect(url_for('login'))

        return render_template("forgot_password.html", form=form)

    @app.route("/email-otp", methods=["GET", "POST"])
    def mail_otp():
     form = OTPForm()
     email = session["email"]
 
     if request.method == "GET" or (request.method == "POST" and 'resend_otp' in request.form):
        if not session.get('OTP_SENT', False) or is_otp_expired() or 'resend_otp' in request.form:
            send_new_otp(email)
            session['OTP_SENT'] = True
            if request.method == "POST":
                return "", 204  # Return empty response for AJAX request

     if request.method == "POST" and 'resend_otp' not in request.form:
        otp_input = request.form["otp"]
        if is_otp_expired():
            flash("OTP has expired. Please try again", "danger")
            return redirect(url_for("register"))
        elif otp_input == session.get("otp"):
            # Save user data to database
            conn = get_db_connection()
            cur = conn.cursor()
          
            cur.execute(
                "INSERT INTO user_profiles (email, username, password, name, birthday, gender, contact, profile_id) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                (session["email"], session["username"], session["password"], f"{session['first_name']} {session['last_name']}", None, None, session["contact"], session["profile_id"])
            )
            conn.commit()
            conn.close()
            session.clear()
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for("login"))
        else:
            flash("Incorrect OTP", "danger")

     return render_template("email_verify.html", form=form)


    def fetch_user_profile(email):
     logging.debug(f"Fetching profile for email: {email}")
     try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM user_profiles WHERE email = %s", (email,))
        profile = cur.fetchone()
        conn.commit()
        conn.close()
        logging.debug(f"Profile fetched: {profile}")
        return profile
     except Exception as e:
        logging.error(f"Error fetching profile for email {email}: {e}")
        return None

    @app.route("/profile", methods=["GET", "POST"])
    @login_required
    def profile():
     email = session.get("login_email") or session.get("user", {}).get("user_info", {}).get("email")
     if not email:
        flash("User email not found in session.", "error")
        return redirect(url_for("login"))

     profile = fetch_user_profile(email)
     if profile is None:
        flash("User profile not found.", "error")
        return redirect(url_for("login"))

     if profile:
        if all(value is not None for value in profile):
            session["user"] = {"email": email} 
            return redirect(url_for("DashBoard"))

     form = UpdateProfileForm()

     if request.method == "POST":
        username = request.form.get("username")
        
        # Check if the new username already exists in the database
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM user_profiles WHERE username = %s AND email != %s", (username, email))
        if cur.fetchone()[0] > 0:
            flash("This username is already taken. Please choose a different one.", "danger")
            conn.close()
            return render_template("profile.html", profile=profile, form=form)
        
        try:
            cur.execute(
                """
                UPDATE user_profiles SET
                    username=%s,
                    name = %s,
                    birthday = %s,
                    gender = %s,
                    contact = %s,
                    organization_name = %s,
                    position = %s
                WHERE email = %s
                """,
                (
                    username,
                    request.form.get("name"),
                    request.form.get("birthday"),
                    request.form.get("gender"),
                    request.form.get("contact"),
                    request.form.get("organization_name"),
                    request.form.get("position"),
                    email
                )
            )
            conn.commit()
            conn.close()
            log_action(email, "Profile updated")
            send_webhook("profile_updated", {
                "email": email,
                "username": username,
                "name": request.form.get("name"),
                "birthday": request.form.get("birthday"),
                "gender": request.form.get("gender"),
                "contact": request.form.get("contact"),
                "organization_name": request.form.get("organization_name"),
                "position": request.form.get("position")
            })
            flash("Profile updated successfully.", "success")
            
            updated_profile = fetch_user_profile(email)
            if any(value is None for value in updated_profile):
                return render_template("profile.html", profile=updated_profile, form=form)
            else:
                session["user"] = {"email": email} 
                return redirect(url_for("DashBoard"))
        except Exception as e:
            logging.error(f"Error updating profile for email {email}: {e}")
            flash("An error occurred while updating the profile.", "error")

     return render_template("profile.html", profile=profile, form=form)


    @app.route("/profile-content", methods=["GET", "POST"])
    @login_required
    def profile_content():
     email = session.get("login_email") or session.get("user", {}).get("user_info", {}).get("email")
     if not email:
        flash("User email not found in session.", "error")
        return redirect(url_for("login"))

     profile = fetch_user_profile(email)
     if profile is None:
        flash("User profile not found.", "error")
        return redirect(url_for("login"))

     if profile:
        if all(value is not None for value in profile):
            session["user"] = {"email": email} 

     form = UpdateProfileForm()

     if request.method == "POST":
        username = request.form.get("username")
        
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM user_profiles WHERE username = %s AND email != %s", (username, email))
        if cur.fetchone()[0] > 0:
            flash("This username is already taken. Please choose a different one.", "danger")
            conn.close()
            return render_template("profile_content.html", profile=profile, form=form)
        
        try:
            cur.execute(
                """
                UPDATE user_profiles SET
                    username=%s,
                    name = %s,
                    birthday = %s,
                    gender = %s,
                    contact = %s,
                    organization_name = %s,
                    position = %s
                WHERE email = %s
                """,
                (
                    username,
                    request.form.get("name"),
                    request.form.get("birthday"),
                    request.form.get("gender"),
                    request.form.get("contact"),
                    request.form.get("organization_name"),
                    request.form.get("position"),
                    email
                )
            )
            conn.commit()
            conn.close()
            log_action(email, "Profile updated")
            send_webhook("profile_updated", {
                "email": email,
                "username": username,
                "name": request.form.get("name"),
                "birthday": request.form.get("birthday"),
                "gender": request.form.get("gender"),
                "contact": request.form.get("contact"),
                "organization_name": request.form.get("organization_name"),
                "position": request.form.get("position")
            })
            flash("Profile updated successfully.", "success")
            
            updated_profile = fetch_user_profile(email)
            if any(value is None for value in updated_profile):
                return render_template("profile_content.html", profile=updated_profile, form=form)
            else:
                session["user"] = {"email": email} 
                return redirect(url_for("DashBoard"))
        except Exception as e:
            logging.error(f"Error updating profile for email {email}: {e}")
            flash("An error occurred while updating the profile.", "error")

     return render_template("profile_content.html", profile=profile, form=form)




    #log function
    def log_action(user_email, action):
     try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("INSERT INTO Userlogs (user_email, action) VALUES (%s, %s)", (user_email, action))
        conn.commit()
        conn.close()
     except Exception as e:
        logging.error(f"Error logging action for user {user_email}: {e}")
        
        
        
        
  
        
        
    
    def send_webhook(event, data):
     webhook_data = {
        "event": event,
        "data": data
     }
    # Print the webhook data to the console
     logging.info(f"Webhook triggered: {json.dumps(webhook_data, indent=4)}")

    # Get the email from the session
     email = session.get("login_email") or session.get("user", {}).get("email")
     if not email:
        logging.error("User email not found in session.")
        return

    # Save the webhook data to the database
     try:
        conn = get_db_connection()
        cur = conn.cursor()
        ist = pytz.timezone('Asia/Kolkata')
        current_time_ist = datetime.now(ist)
        cur.execute("""
            INSERT INTO webhooks (email, event, data, created_at)
            VALUES (%s, %s, %s, %s)
        """, (email, event, json.dumps(data), current_time_ist))
        conn.commit()
        cur.close()
        conn.close()
        logging.info("Webhook data saved to the database successfully.")
     except Exception as e:
        logging.error(f"Error saving webhook data: {e}")
    @app.route('/webhooks', methods=['GET'])
    def get_webhooks():
     try:
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 10))
        offset = (page - 1) * limit

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT email, event, data, created_at 
            FROM webhooks
            ORDER BY created_at DESC
            LIMIT %s OFFSET %s
        """, (limit, offset))
        rows = cur.fetchall()
        cur.close()
        conn.close()

        webhooks = []
        for row in rows:
           
            created_at_utc = row[3]
            created_at_ist = created_at_utc.astimezone(pytz.timezone('Asia/Kolkata'))
            formatted_date = created_at_ist.strftime('%d-%m-%Y %H:%M:%S')
            webhooks.append({
                'email': row[0],
                'event': row[1],
                'data': json.loads(row[2]),
                'created_at': formatted_date
            })

        return jsonify(webhooks)
     except Exception as e:
        logging.error(f"Error fetching webhooks: {e}")
        return jsonify({'error': 'Failed to fetch webhooks'}), 500




    @app.route('/dashboard/add_device', methods=['GET', 'POST'])
    @login_required
    def add_device():
     form = AddDeviceForm()
     if form.validate_on_submit():
        email = session.get("login_email") or session.get("user", {}).get("email")
        if not email:
            flash("User email not found in session.", "error")
            return redirect(url_for("login"))

        form_data = {
            "entityName": form.entityName.data,
            "deviceIMEI": form.deviceIMEI.data,
            "simICCId": form.simICCId.data,
            "batterySLNo": form.batterySLNo.data,
            "panelSLNo": form.panelSLNo.data,
            "luminarySLNo": form.luminarySLNo.data,
            "mobileNo": form.mobileNo.data,
            "district": form.district.data,
            "panchayat": form.panchayat.data,
            "block": form.block.data,
            "wardNo": form.wardNo.data,
            "poleNo": form.poleNo.data,
            "active": form.active.data,
            "installationDate": form.installationDate.data,
        }

        # Log the form data for debugging
        print("Form Data:", form_data)

        try:
            conn = get_db_connection()
            cur = conn.cursor()

            # Check for duplicate deviceIMEI
            cur.execute("SELECT COUNT(*) FROM devices WHERE deviceIMEI = %s", (form_data["deviceIMEI"],))
            if cur.fetchone()[0] > 0:
                flash("A device with this IMEI already exists.", "danger")
                conn.close()
                return render_template('add_device.html', form=form)
            ist = pytz.timezone('Asia/Kolkata')
            current_time_ist = datetime.now(ist)

            cur.execute("""
                INSERT INTO devices (email, entityName, deviceIMEI, simICCId, batterySLNo, panelSLNo, luminarySLNo, mobileNo, district, panchayat, block, wardNo, poleNo, active, installationDate, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                email,
                form_data["entityName"],
                form_data["deviceIMEI"],
                form_data["simICCId"],
                form_data["batterySLNo"],
                form_data["panelSLNo"],
                form_data["luminarySLNo"],
                form_data["mobileNo"],
                form_data["district"],
                form_data["panchayat"],
                form_data["block"],
                form_data["wardNo"],
                form_data["poleNo"],
                form_data["active"],
                form_data["installationDate"],
                current_time_ist,
            ))
            conn.commit()
            cur.close()
            conn.close()

            log_action(email, "Device added")
            send_webhook("device_added", form_data)

            flash("Device added successfully!", "success")
            return redirect(url_for('DashBoard'))
        except Exception as e:
            logging.error(f"Error adding device for email {email}: {e}")
            flash("An error occurred while adding the device.", "error")

     return render_template( 'dashboard.html',form=form)
      
    @app.route('/dashboard/view_devices', methods=['GET'])
    def view_devices():
     email = session.get("login_email") or session.get("user", {}).get("email")
     if not email:
        flash("User email not found in session.", "error")
        return redirect(url_for("login"))

     page = int(request.args.get('page', 1))
     page_size = int(request.args.get('page_size', 10))
     offset = (page - 1) * page_size

     try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM devices WHERE email = %s LIMIT %s OFFSET %s", (email, page_size, offset))
        devices = cur.fetchall()
        cur.execute("SELECT COUNT(*) FROM devices WHERE email = %s", (email,))
        total_devices = cur.fetchone()[0]
     except Exception as e:
        return jsonify({"error": str(e)})
     finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

     devices_data = []
     for device in devices:
        device_data = {
            "entityName": device[2],
            "deviceIMEI": device[3],
            "simICCId": device[4],
            "batterySLNo": device[5],
            "panelSLNo": device[6],
            "luminarySLNo": device[7],
            "mobileNo": device[8],
            "district": device[9],
            "panchayat": device[10],
            "block": device[11],
            "wardNo": device[12],
            "poleNo": device[13],
            "active": device[14],
            "installationDate": device[15],
        }
        devices_data.append(device_data)

     return jsonify({
        "devices": devices_data,
        "total_devices": total_devices,
        "page": page,
        "page_size": page_size
     })


 

    @app.route('/dashboard/request_device', methods=['GET', 'POST'])
    @login_required
    def request_device():
     form = RequestDeviceForm()
     email = session.get("login_email") or session.get("user", {}).get("email")
     if not email:
        flash("User email not found in session.", "error")
        return redirect(url_for("login"))

    # Check if there's a pending request for this email
     try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT status FROM device_requests WHERE email = %s AND status = 'pending'
        """, (email,))
        pending_request = cur.fetchone()
        
        if pending_request:
            return jsonify({"status": "pending"}), 200
        
        cur.close()
        conn.close()
     except Exception as e:
        logging.error(f"Error checking pending request for email {email}: {e}")
        return jsonify({"error": "An error occurred while checking pending requests."}), 500

     if form.validate_on_submit():
        device_count = form.device_count.data

        try:
            conn = get_db_connection()
            cur = conn.cursor()
            ist = pytz.timezone('Asia/Kolkata')
            current_time_ist = datetime.now(ist)
           

            # Insert the device request into the device_requests table
            cur.execute("""
                INSERT INTO device_requests (email, device_count, status, created_at)
                VALUES (%s, %s, %s, %s)
            """, (email, device_count, 'pending', current_time_ist))
            conn.commit()
            cur.close()
            conn.close()

            log_action(email, "Device request submitted")
            send_webhook("device_request_submitted", {"email": email, "device_count": device_count})

            flash("Device request submitted successfully!", "success")
            return redirect(url_for('DashBoard'))
        except Exception as e:
            logging.error(f"Error requesting device for email {email}: {e}")
            flash("An error occurred while submitting the device request.", "error")
            return redirect(url_for('request_device'))

     return render_template('dashboard.html', form=form)

    @app.route('/dashboard/get_device_list', methods=['GET'])
    @login_required
    def get_device_list():
     email = session.get("login_email") or session.get("user", {}).get("email")
     if not email:
        return jsonify({"error": "User email not found in session."}), 400

     try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT device_id FROM token_device WHERE email = %s
        """, (email,))
        devices = cur.fetchall()
        cur.close()
        conn.close()

        device_list = [{"device_id": device[0]} for device in devices]
        return jsonify({"devices": device_list})
     except Exception as e:
        logging.error(f"Error fetching device list for email {email}: {e}")
        return jsonify({"error": "An error occurred while fetching the device list."}), 500

    
    @app.route('/dashboard/get_request_status', methods=['GET'])
    @login_required
    def get_request_status():
     email = session.get("login_email") or session.get("user", {}).get("email")
     if not email:
        return jsonify({"error": "User email not found in session."}), 400

     try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT status FROM device_requests WHERE email = %s ORDER BY created_at DESC LIMIT 1
        """, (email,))
        request_status = cur.fetchone()
        cur.close()
        conn.close()

        if request_status:
            return jsonify({"status": request_status[0]})
        else:
            return jsonify({"status": "none"})
     except Exception as e:
        logging.error(f"Error fetching request status for email {email}: {e}")
        return jsonify({"error": "An error occurred while fetching the request status."}), 500
    
    @app.route('/dashboard/check_device_requests', methods=['GET'])
    @login_required
    def check_device_requests():
     email = session.get("login_email") or session.get("user", {}).get("email")
     if not email:
        return jsonify({"error": "User email not found in session."}), 400

     try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT SUM(device_count) FROM device_requests WHERE email = %s AND status = 'approved'
        """, (email,))
        device_request_count = cur.fetchone()[0] or 0

        cur.execute("""
            SELECT COUNT(*) FROM devices WHERE email = %s
        """, (email,))
        device_count = cur.fetchone()[0] or 0

        cur.close()
        conn.close()

        return jsonify({
            "requested_devices": device_request_count,
            "added_devices": device_count
        }), 200
     except Exception as e:
        logging.error(f"Error checking device requests for email {email}: {e}")
        return jsonify({"error": "An error occurred while checking device requests."}), 500


  
    @app.route('/admindashboard/approve_device_requests', methods=['GET', 'POST'])
    @login_required
    def approve_device_requests():
     if request.method == 'POST':
        try:
            data = request.json
            request_id = data.get('request_id')
            approval_status = data.get('approval_status')
            email = data.get('email')
            device_count = data.get('device_count')

            logging.info(f"request_id: {request_id} ({type(request_id)}), approval_status: {approval_status} ({type(approval_status)}), email: {email} ({type(email)}), device_count: {device_count} ({type(device_count)})")

            conn = get_db_connection()
            cur = conn.cursor()

            # Update device request status using email
            sql_query = "UPDATE device_requests SET status = %s WHERE email = %s"
            sql_params = (approval_status, email)

            logging.info(f"Executing SQL: {sql_query} with params: {sql_params}")

            cur.execute(sql_query, sql_params)
            conn.commit()

            # Fetch device IDs from token_device table linked with the same email
            cur.execute("SELECT device_id FROM token_device WHERE email = %s", (email,))
            device_ids = cur.fetchall()

            logging.info(f"Device IDs: {device_ids}")

            # Log action
            log_action(email, f"Device request {approval_status}")

            # Send webhook
            if approval_status == 'approved':
                send_webhook("device_request_approved", {"request_id": request_id, "email": email})
                # Create tables for each approved device
                for device_id in device_ids:
                    create_device_table(device_id[0])  # Use device_id[0] as device_id is a tuple
            elif approval_status == 'rejected':
                send_webhook("device_request_rejected", {"request_id": request_id, "email": email})

            cur.close()
            conn.close()
            return jsonify({"message": "Device request processed successfully!"}), 200
        except Exception as e:
            logging.error(f"Error processing device request: {str(e)}")
            return jsonify({"message": "An error occurred while processing the device request."}), 500

     try:
        conn = get_db_connection()
        cur = conn.cursor()
        # Fetch pending requests
        cur.execute("SELECT id, email, device_count FROM device_requests WHERE status = 'pending'")
        pending_requests = cur.fetchall()
        pending_requests_dicts = [dict(zip([key[0] for key in cur.description], row)) for row in pending_requests]

        cur.close()
        conn.close()
        return jsonify(pending_requests_dicts), 200
     except Exception as e:
        logging.error(f"Error fetching pending device requests: {str(e)}")
        return jsonify({"message": "An error occurred while fetching pending device requests."}), 500


    def create_device_table(device_id):
     conn = get_db_connection()
     cursor = conn.cursor()
     cursor.execute(f'''
        CREATE TABLE IF NOT EXISTS device_{device_id} (
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            BC REAL,
            BCPr REAL,
            BDPr REAL,
            BF REAL,
            BP REAL,
            BTem REAL,
            BV REAL,
            BrL REAL,
            GIS TEXT,
            GPSP REAL,
            HEn REAL,
            LC REAL,
            LF REAL,
            LP REAL,
            LSt REAL,
            LV REAL,
            MF REAL,
            PC REAL,
            PP REAL,
            PV REAL,
            SSL_ID TEXT,
            SSt INTEGER,
            S_ID TEXT
        )
    ''')
     conn.commit()
     conn.close()
 
    

    @app.route('/device_data', methods=['POST'])
    def device_data():
     data = request.json
     device_id = data.get('D_ID')
    
     if not device_id:
        return jsonify({'message': 'Device ID is required'}), 400

     create_device_table(device_id)
 
     conn = get_db_connection()
     cursor = conn.cursor()
    
     placeholders = ', '.join('?' * len(data.keys()))
     columns = ', '.join(data.keys())
     sql = f'INSERT INTO device_{device_id} ({columns}) VALUES ({placeholders})'
     cursor.execute(sql, list(data.values()))
    
     conn.commit()
     conn.close()

     return jsonify({'message': f'Data for device {device_id} saved'}), 200

    @app.route('/analytics', methods=['GET'])
    def analytics():
     conn = get_db_connection()
     cursor = conn.cursor()
     cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'device_%'")
     device_tables = [row['name'] for row in cursor.fetchall()]
     conn.close()

     return render_template('analytics.html', devices=device_tables)

    @app.route('/fetch_device_data/<device_id>', methods=['GET'])
    def fetch_device_data(device_id):
     conn = get_db_connection()
     cursor = conn.cursor()
     one_month_ago = datetime.now() - timedelta(days=30)
     cursor.execute(f'''
        SELECT * FROM device_{device_id}
        WHERE timestamp >= ?
     ''', (one_month_ago,))
     data = cursor.fetchall()
     conn.close()

     return jsonify([dict(row) for row in data])
  
   
    
    @app.route('/dashboard/check_device_added', methods=['GET'])
    def check_device_added():
     email = session.get("login_email") or session.get("user", {}).get("email")
     conn = get_db_connection()
     cursor = conn.cursor()

     query = 'SELECT COUNT(*) as count FROM devices WHERE email = %s'
     cursor.execute(query, (email,))
     result = cursor.fetchone()

     cursor.close()
     conn.close()
 
     if result[0] > 0:
        return jsonify(device_added=True)
     else:
        return jsonify(device_added=False)
    
    def get_ist_time():
     utc_time = datetime.now()
     ist_time = utc_time.replace(tzinfo=pytz.utc).astimezone(pytz.timezone('Asia/Kolkata'))
     return ist_time.isoformat()

    @app.route('/data')
    def data():
    # Data Format: [TIME, Temperature, Humidity]
     temperature = random.random() * 100
     humidity = random.random() * 55

     data = [time() * 1000, temperature, humidity]

     response = make_response(json.dumps(data))
     response.content_type = 'application/json'

     return response

    @app.route('/data1')
    def data1():
     return jsonify(
        time=get_ist_time(),
        voltage=round(random.uniform(5, 15), 1),
        current=round(random.uniform(1, 6), 1)
     )



    #SECRET_TOKEN = os.environ.get('SECRET_TOKEN', 'default_secret_token')
     #SECRET_TOKEN = os.environ.get('SECRET_TOKEN', 'default_secret_token')
    SECRET_TOKEN = "tR7Hs9Ky3Lm1Pq4Xw2Zb8Nf5Vj7Cd6"
    if not SECRET_TOKEN:
        raise ValueError("SECRET_TOKEN environment variable is not set")
    
    def require_auth(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            auth_header = request.headers.get('Authorization')
            if not auth_header:
                return jsonify({"error": "Authorization header is missing"}), 401
            try:
                auth_type, token = auth_header.split()
                
                if auth_type.lower() != 'bearer':
                    return jsonify({"error": "Bearer token required"}), 401
                
                # Use secrets.compare_digest for secure string comparison
                if not secrets.compare_digest(token, SECRET_TOKEN):
                    return jsonify({"error": "Invalid token"}), 401
            except ValueError:
                return jsonify({"error": "Invalid Authorization header format"}), 401
            return f(*args, **kwargs)
        return decorated
    

    @app.route('/protected')
    @require_auth
    def protected():
        return jsonify({"message": "This is a protected route"})

    @app.route("/device", methods=['GET'])
    @require_auth
    def handle_device():
        device_id = request.args.get('device_id')
        if not device_id:
            return jsonify({"error": "No device ID provided"}), 400
        
        conn = get_db_connection()
        cur = conn.cursor()
        
        try:
            # Generate a new token (you may want to use a more secure method)
            new_token = secrets.token_hex(10)
            
            # Insert or update the device
            cur.execute("""
                INSERT INTO token_device (Device_id, Token_id) 
                VALUES (%s, %s) 
                ON DUPLICATE KEY UPDATE Token_id = VALUES(Token_id)
            """, (device_id, new_token))
            conn.commit()
            
            return jsonify({"device_id": device_id, "token": new_token}), 200
        
        except pymysql.IntegrityError as e:
            conn.rollback()
            if e.args[0] == 1062:  # Duplicate entry error
                return jsonify({"error": "Device ID already exists"}), 409
            else:
                return jsonify({"error": "Database integrity error"}), 500
        except Exception as e:
            conn.rollback()
            return jsonify({"error": str(e)}), 500
        
        finally:
            cur.close()
            conn.close()
