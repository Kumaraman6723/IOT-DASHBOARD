from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from models import fetch_email, recover_passkey, fetch_users, get_db_connection
from email_service import send_email
from forms import RegisterForm, UpdateProfileForm, VerificationForm, OTPForm, ForgetPass
from utils import otpmaker, check_password
from config import appConf, SITE_KEY, SECRET_KEY
from werkzeug.security import generate_password_hash
from authlib.integrations.flask_client import OAuth
from authlib.integrations.base_client import OAuthError
import requests
import json
import time
from datetime import datetime
import uuid
import logging

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

            if not outcome['success']:
                flash('The provided Turnstile token was not valid!', 'error')
                return redirect(url_for('login'))

            email = request.form["email"]
            password = request.form["password"]
            user = next((x for x in store if x[0] == email), None)

            if user and check_password(user[1], password):
                session["login_email"] = email
                return redirect(url_for('two_step'))
            else:
                flash("Invalid email or password", "error")

        return render_template("login.html", site_key=SITE_KEY)

    # Home route
    @app.route("/home")
    @login_required
    def home():
        return render_template("home.html", session=session.get("user"),
                               pretty=json.dumps(session.get("user"), indent=4))

    # Google OAuth routes
# Google OAuth routes
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

        if existing_user:
            # Check if the user profile is complete (no null values)
            if all(value is not None for value in existing_user):
                conn.close()
                return redirect(url_for("DashBoard"))

        cur.execute(
            "INSERT INTO user_profiles (email, name, birthday, gender, contact, profile_id) VALUES (%s, %s, %s, %s, %s, %s) "
            "ON DUPLICATE KEY UPDATE name=%s, birthday=%s, gender=%s, contact=%s",
            (email, f"{first_name} {last_name}", birthday, gender, None, profile_id, f"{first_name} {last_name}", birthday, gender, None)
        )
        conn.commit()
        conn.close()

        return redirect(url_for("profile"))

    @app.route("/google-login")
    def googleLogin():
        session.clear()
        redirect_uri = url_for("googleCallback", _external=True)
        return oauth.myApp.authorize_redirect(redirect_uri=redirect_uri)
    # Logout route
    @app.route("/logout")
    def logout():
        if "user" in session:
            token = session["user"].get("access_token")
            if token:
                requests.post("https://accounts.google.com/o/oauth2/revoke", params={"token": token})
        session.clear()
        return redirect(url_for("login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        form = RegisterForm()
        if form.validate_on_submit():
            hash_and_salted_password = generate_password_hash(
                form.password.data, method='pbkdf2:sha256', salt_length=8)
            
            profile_id = str(uuid.uuid4())  # Generate a unique profile ID

            session.update({
                "first_name": form.first_name.data,
                "last_name": form.last_name.data,
                "email": form.email.data,
                "password": hash_and_salted_password,
                "contact": form.contact.data,
                "profile_id": profile_id
            })

            if session["email"] in fetch_email():
                flash("This email is already registered. Please use a different email.", "danger")
            else:
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
    @app.route("/DashBoard", methods=["GET", "POST"])
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

        return render_template("forgot_pass.html", form=form)

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
                    "INSERT INTO user_profiles (email, name, birthday, gender, contact, profile_id) VALUES (%s, %s, %s, %s, %s, %s)",
                    (session["email"], f"{session['first_name']} {session['last_name']}", None, None, session["contact"], session["profile_id"])
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
            # Check if the user profile is complete (no null values)
            if all(value is not None for value in profile):
                
                return redirect(url_for("DashBoard"))

        form = UpdateProfileForm()

        if request.method == "POST":
            try:
                conn = get_db_connection()
                cur = conn.cursor()
                cur.execute(
                    """
                    UPDATE user_profiles SET
                        name = %s,
                        birthday = %s,
                        gender = %s,
                        contact = %s,
                        company_name = %s,
                        position = %s
                    WHERE email = %s
                    """,
                    (
                        request.form.get("name"),
                        request.form.get("birthday"),
                        request.form.get("gender"),
                        request.form.get("contact"),
                        request.form.get("orgName"),
                        request.form.get("position"),
                        email
                    )
                )
                conn.commit()
                conn.close()
                flash("Profile updated successfully.", "success")
                    # Check for null values after update
                updated_profile = fetch_user_profile(email)
                if any(value is None for value in updated_profile.values()):
                 return render_template("profile.html", profile=updated_profile)
                else:
                 return redirect(url_for("DashBoard"))
            except Exception as e:
             logging.error(f"Error updating profile for email {email}: {e}")
             flash("An error occurred while updating the profile.", "error")

             return redirect(url_for("DashBoard"))
        return render_template("profile.html", profile=profile)


        

