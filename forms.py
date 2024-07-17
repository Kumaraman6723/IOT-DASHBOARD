from flask_wtf import FlaskForm
from wtforms import SelectField, StringField, DateField, SubmitField, TelField
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField,validators
from wtforms.validators import DataRequired, Email, EqualTo, Length, Regexp, ValidationError
import re

def validate_contact(form, field):
        if not re.match(r'^[0-9]+$', field.data):
            raise ValidationError('Contact should contain only numbers.')


class RegisterForm(FlaskForm):
    username = StringField('Username', [
        validators.DataRequired(),
        validators.Length(min=4, max=25)
    ])
    first_name = StringField("First Name", validators=[DataRequired()])
    last_name = StringField("Last Name")
    email = StringField("Email", validators=[DataRequired(), Email()])

    contact = StringField("Contact", validators=[DataRequired(),validate_contact])

    password = PasswordField("Password", validators=[
        
        DataRequired(),
        Length(min=8, message='Password must be at least 8 characters long.'),
        Regexp(r'^(?=.*[A-Z])', message='Password must contain at least one uppercase letter.'),
        Regexp(r'^(?=.*[a-z])', message='Password must contain at least one lowercase letter.'),
        Regexp(r'^(?=.*\d)', message='Password must contain at least one digit.'),
        Regexp(r'^(?=.*[!@#$%^&*(),.?":{}|<>])', message='Password must contain at least one special character.')

    ])


    confirm_password = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo('password', message='Passwords must match')])
    submit = SubmitField("Submit")


class VerificationForm(FlaskForm):
    email = StringField('Email address', validators=[DataRequired(), Email()])
    submit = SubmitField('Next')



class OTPForm(FlaskForm):
     otp = PasswordField("Enter OTP",validators=[DataRequired(),])
     submit = SubmitField('Submit')



class ForgetPass(FlaskForm):

        password = PasswordField("New Password", validators=[
        
        DataRequired(),
        Length(min=8, message='Password must be at least 8 characters long.'),
        Regexp(r'^(?=.*[A-Z])', message='Password must contain at least one uppercase letter.'),
        Regexp(r'^(?=.*[a-z])', message='Password must contain at least one lowercase letter.'),
        Regexp(r'^(?=.*\d)', message='Password must contain at least one digit.'),
        Regexp(r'^(?=.*[!@#$%^&*(),.?":{}|<>])', message='Password must contain at least one special character.')

    ])
        confirm_password = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo('password', message='Passwords must match')])
        submit = SubmitField("Change Password")
        
class UpdateProfileForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(message="Username is required"),
        Length(min=2, max=20, message="Username must be between 2 and 20 characters")
    ])
    email = StringField('Email', validators=[
        DataRequired(message="Email is required"),
        Email(message="Enter a valid email address")
    ])
    name = StringField('Full Name', validators=[
        DataRequired(message="Name is required"),
        Length(max=100, message="Name must be 100 characters or fewer")
    ])
    birthday = DateField('Birthday', format='%Y-%m-%d', validators=[
        DataRequired(message="Birthday is required"),
        Regexp(regex=r'\d{4}-\d{2}-\d{2}', message="Date must be in YYYY-MM-DD format")
    ])
    gender = SelectField('Gender', choices=[
        ('', 'Select Gender'),
        ('male', 'Male'),
        ('female', 'Female'),
        ('other', 'Other')
    ], validators=[DataRequired(message="Gender is required")])
    contact = StringField('Contact Number', validators=[
        DataRequired(message="Contact number is required"),
        Length(max=20, message="Contact number must be 20 characters or fewer")
    ])
    organization_name = StringField('Organization Name', validators=[
        DataRequired(message="Organization name is required"),
        Length(max=100, message="Organization name must be 100 characters or fewer")
    ])
    position = StringField('Position', validators=[
        DataRequired(message="Position is required"),
        Length(max=100, message="Position must be 100 characters or fewer")
    ])
    submit = SubmitField('Update Profile')

class AddDeviceForm(FlaskForm):
    entityName = StringField('Entity Name', validators=[DataRequired()])
    deviceIMEI = StringField('Device IMEI', validators=[DataRequired()])
    simICCId = StringField('SIM ICC ID', validators=[DataRequired()])
    batterySLNo = StringField('Battery SL No', validators=[DataRequired()])
    panelSLNo = StringField('Panel SL No', validators=[DataRequired()])
    luminarySLNo = StringField('Luminary SL No', validators=[DataRequired()])
    mobileNo = StringField('Mobile No', validators=[DataRequired()])
    district = StringField('District', validators=[DataRequired()])
    panchayat = StringField('Panchayat', validators=[DataRequired()])
    block = StringField('Block', validators=[DataRequired()])
    wardNo = StringField('Ward No', validators=[DataRequired()])
    poleNo = StringField('Pole No', validators=[DataRequired()])
    active = SelectField('Active', choices=[('true', 'True'), ('false', 'False')], validators=[DataRequired()])
    installationDate = StringField('Installation Date', validators=[DataRequired()])
    submit = SubmitField('Submit')
