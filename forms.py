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
    entityName = StringField('Entity Name', validators=[
        DataRequired(message="Entity Name is required"),
        Length(max=100, message="Entity Name must be 100 characters or fewer")
    ])
    deviceIMEI = StringField('Device IMEI', validators=[
        DataRequired(message="Device IMEI is required"),
        Length(max=100, message="Device IMEI must be 100 characters or fewer")
    ])
    simICCId = StringField('SIM ICC ID', validators=[
        DataRequired(message="SIM ICC ID is required"),
        Length(max=100, message="SIM ICC ID must be 100 characters or fewer")
    ])
    batterySLNo = StringField('Battery SL No', validators=[
        DataRequired(message="Battery SL No is required"),
        Length(max=100, message="Battery SL No must be 100 characters or fewer")
    ])
    panelSLNo = StringField('Panel SL No', validators=[
        DataRequired(message="Panel SL No is required"),
        Length(max=100, message="Panel SL No must be 100 characters or fewer")
    ])
    luminarySLNo = StringField('Luminary SL No', validators=[
        DataRequired(message="Luminary SL No is required"),
        Length(max=100, message="Luminary SL No must be 100 characters or fewer")
    ])
    mobileNo = StringField('Mobile No', validators=[
        DataRequired(message="Mobile No is required"),
        Length(max=20, message="Mobile No must be 20 characters or fewer")
    ])
    district = StringField('District', validators=[
        DataRequired(message="District is required"),
        Length(max=100, message="District must be 100 characters or fewer")
    ])
    panchayat = StringField('Panchayat', validators=[
        DataRequired(message="Panchayat is required"),
        Length(max=100, message="Panchayat must be 100 characters or fewer")
    ])
    block = StringField('Block', validators=[
        DataRequired(message="Block is required"),
        Length(max=100, message="Block must be 100 characters or fewer")
    ])
    wardNo = StringField('Ward No', validators=[
        DataRequired(message="Ward No is required"),
        Length(max=100, message="Ward No must be 100 characters or fewer")
    ])
    poleNo = StringField('Pole No', validators=[
        DataRequired(message="Pole No is required"),
        Length(max=100, message="Pole No must be 100 characters or fewer")
    ])
    active = SelectField('Active', choices=[
        ('true', 'True'),
        ('false', 'False')
    ], validators=[DataRequired(message="Active status is required")])
    installationDate = DateField('Installation Date', format='%Y-%m-%d', validators=[
        DataRequired(message="Installation Date is required"),
        Regexp(regex=r'\d{4}-\d{2}-\d{2}', message="Date must be in YYYY-MM-DD format")
    ])
    submit = SubmitField('Add Device')
