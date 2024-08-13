from flask import Flask ,render_template ,redirect ,url_for,session,flash
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField
from wtforms.validators import DataRequired ,Email ,ValidationError
# from flask_bcrypt import Bcrypt
import bcrypt
import email_validator

from flask_mysqldb import MySQL

app=Flask(__name__)


mysql=MySQL(app)
# bcrypt=Bcrypt(app)









#  my sql configration

app.config['MYSQL_HOST']='localhost'
app.config['MYSQL_USER']='root'
app.config['MYSQL_PASSWORD']=''
app.config['MYSQL_DB']='mydatabase'
app.secret_key='your_secret_key'



class RegistrationForm(FlaskForm):
    name=StringField("Name",validators=[DataRequired()])
    email=StringField("Email",validators=[DataRequired(), Email()])
    password=PasswordField("Password",validators=[DataRequired()])
    submit=SubmitField("Register")

    def validate_email(self,field):
        cursor=mysql.connection.cursor()
        cursor.execute("SELECT * FROM users where email=%s",(field.data,))
        user=cursor.fetchone()
        cursor.close()

        if user:
            raise ValidationError('Email is already taken')


class LoginForm(FlaskForm):
    
    email=StringField("Email",validators=[DataRequired(), Email()])
    password=PasswordField("Password",validators=[DataRequired()])
    submit=SubmitField("Login")



@app.route('/')
def index():
    return render_template('hello.html')


@app.route('/register', methods=['GET','POST'])
def register():

    form= RegistrationForm()
    if form.validate_on_submit():
        name=form.name.data
        email=form.email.data
        password=form.password.data


        hashed_password= bcrypt.hashpw(password.encode('utf-8'),bcrypt.gensalt())
      
    #   connection yaha se establish hoga
        cursor=mysql.connection.cursor()
        cursor.execute("INSERT INTO users(name,email,password)VALUES(%s,%s,%s)",(name,email,hashed_password)) 
        mysql.connection.commit()
        cursor.close()

        return redirect(url_for('login'))



    return render_template('register.html',form=form)


@app.route('/login', methods=['GET','POST'])
def login():
    form= LoginForm()
    if form.validate_on_submit():
        
        email=form.email.data
        password=form.password.data


        
      
    #   
        cursor= mysql.connection.cursor()
        # selecting the user on the behalf on email
        cursor.execute("SELECT * FROM users WHERE email= %s ",(email,))
        user=cursor.fetchone()
        
        cursor.close()
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user[3].encode('utf-8')):

            session['user_id']=user[0]
            return redirect(url_for('dashboard'))
        else:
            flash("login failed . please check your email and password")
            return redirect(url_for('login'))


        # return redirect(url_for('login'))



    return render_template('login.html',form=form)

    # return render_template('login.html')


@app.route('/dashboard')
def dashboard():

    if 'user_id' in session:
        user_id=session['user_id']

        cursor=mysql.connection.cursor()
        cursor.execute("Select * From users where id=%s",(user_id,))
        user=cursor.fetchone()
        cursor.close()

        if user:
            return render_template('dashboard.html',user=user)
        

    return redirect(url_for('login'))
    
    
    
    # return render_template('dashboard.html')

@app.route('/logout')
def logout():
    session.pop('user_id',None)
    flash(" You Have Successfully logged out")
    return redirect(url_for('login'))


@app.route('/courses')
def superr():
    return render_template('courses.html')

@app.route('/aboutus')
def about():
    return render_template('aboutus.html')


@app.route('/community')
def community():
    return render_template('communitysec.html')



if __name__=='__main__':
    app.run(debug=True)