from flask import Flask,render_template,flash,redirect,url_for,session,logging,request,g
from flask_mysqldb import MySQL
from wtforms import Form,StringField,TextAreaField,PasswordField,validators, SubmitField
from passlib.hash import sha256_crypt 
from functools import wraps
import hashlib

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "logged_in" in session:
            return f(*args, **kwargs)
        else:
            flash("Bu sayfayı görüntüleme izniniz yok", "danger")
            return redirect(url_for("index"))
    return decorated_function
 
 
app = Flask(__name__)
app.secret_key= "gorevdefterisecretkey"
 
app.config["MYSQL_HOST"] = "localhost"
app.config["MYSQL_USER"] = "root"
app.config["MYSQL_PASSWORD"] = ""
app.config["MYSQL_DB"] = "gorevdefteri"
app.config["MYSQL_CURSORCLASS"] = "DictCursor"


 
mysql = MySQL(app)


@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm(request.form)

    if request.method == "POST" and form.validate():
        username = form.username.data
        email = form.email.data
        phone = form.phone.data
        password = form.password.data
        password_again = form.passwordAgain.data

        cursor = mysql.connection.cursor()

        # Kullanıcı adının veritabanında zaten var olup olmadığını kontrol et
        check_query = "SELECT * FROM users WHERE username = %s"
        result = cursor.execute(check_query, (username,))

        if result > 0:
            flash("Bu kullanıcı adı zaten kayıtlı.", "danger")
            return redirect(url_for("register"))

        if password == password_again:
            hashed_password = sha256_crypt.encrypt(password)

            insert_query = "INSERT INTO users (username, email, phone, password) VALUES (%s, %s, %s, %s)"
            cursor.execute(insert_query, (username, email, phone, hashed_password))
            mysql.connection.commit()
            cursor.close()

            flash("Başarıyla kayıt oldunuz!", "success")
            return redirect(url_for("login"))
        else:
            flash("Girdiğiniz şifreler uyuşmuyor!", "danger")

    return render_template("register.html", form=form)



@app.route("/login", methods = ["GET", "POST"])
def login():
    form = LoginForm(request.form)

    if request.method == "POST" and form.validate():
        username_entered = form.username.data
        password_entered = form.password_entered.data

        cursor = mysql.connection.cursor()
        sorgu = "SELECT * FROM users WHERE username = %s"
        result = cursor.execute(sorgu, (username_entered,))
        
        if result > 0:
            data = cursor.fetchone()  # Fetch the first matching row
            stored_password = data["password"]
            
            if sha256_crypt.verify(password_entered, stored_password):
                # Password is correct
                session["logged_in"] = True
                session["username"] = username_entered
                flash("Başarıyla giriş yaptınız.", "success")
                return redirect(url_for("ajandam", username=session["username"]))
            else:
                flash("Parola yanlış.", "danger")
                return redirect(url_for("login"))
        else:
            flash("Kullanıcı bulunamadı.", "danger")
            return redirect(url_for("login"))

    return render_template("login.html", form=form)


@app.route("/logout")
def logout():
    session.clear()
    flash("Başarıyla Çıkış Yaptınız.", "success")
    return redirect(url_for("login"))


@app.route("/profile/<string:username>")
@login_required
def profile(username):
    if session["username"] == username:
        cursor = mysql.connection.cursor()
        sorgu = "SELECT * FROM users WHERE username = %s"
        result = cursor.execute(sorgu, (username,))

        if result > 0:
            user_data = cursor.fetchone()  
            return render_template("profile.html", user_data=user_data)
        else:
            flash("Kullanıcı bulunamadı.", "danger")
            return redirect(url_for("index"))
    else:
        flash("Bu profil sayfasını görüntüleme yetkiniz yok.", "danger")
        return redirect(url_for("index"))
    

@app.route("/edit/<string:username>", methods = ["GET", "POST"])
@login_required
def editprofile(username):
    if request.method == "GET":
        cursor = mysql.connection.cursor()

        sorgu = "Select * from users where username = %s"
        result = cursor.execute(sorgu,(session["username"],))

        if result == 0:
            flash("Böyle bir profil yok veya yetkiniz yok", "danger")
            return redirect(url_for("index"))
        else:
            userData = cursor.fetchone()

            form = RegisterForm()

            form.username.data = userData["username"]
            form.email.data = userData["email"]
            form.phone.data = userData["phone"]

            return render_template("editprofile.html", form = form)
    elif request.method == "POST":
        data_cursor = mysql.connection.cursor()
        data_sorgu = "Select * from users where username = %s"
        data_result = data_cursor.execute(data_sorgu,(session["username"],))

        if data_result > 0:
            user_Data = data_cursor.fetchone()
            data_cursor.close()

        
        form = RegisterForm(request.form)


        if form.validate() == False:
            newUsername = form.username.data
            newEmail = form.email.data
            newPhone = form.phone.data
            newPassword = form.password.data

 
            if sha256_crypt.verify(form.password.data, user_Data["password"]):
                password_hash = sha256_crypt.encrypt(newPassword)
                
                sorgu2 = "UPDATE users SET username = %s, email = %s, phone = %s, password = %s WHERE username = %s"

                cursor = mysql.connection.cursor()

                cursor.execute(sorgu2, (newUsername, newEmail, newPhone, password_hash ,session["username"]))

                mysql.connection.commit()

                session.clear()
                flash("Bilgileriniz Başarıyla Güncellendi! Lütfen Tekrar Giriş Yapınız", "success")
                return redirect(url_for("login"))
            else:
                flash("Girilen şifreler eşleşmiyor.", "danger")
                return render_template("editprofile.html", form=form)

  

            
        else:
            flash("Güncelleme Başarısız. Lütfen Tekrar Deneyiniz.", "danger")
            
            return render_template("editprofile.html", form=form)
        

    
@app.route("/ajandam/<string:username>", methods = ["GET", "POST"])
@login_required
def ajandam(username): 
    addNotes = AddNotesForm(request.form)
    if request.method == "GET":


        cursor = mysql.connection.cursor()

        sorgu = "Select * from users where username = %s"
        result = cursor.execute(sorgu,(session["username"],))


        if result == 0:
            flash("Böyle bir ajanda yok veya yetkiniz yok", "danger")
            return redirect(url_for("index"))
        
        else:
            return render_template("ajandam.html", addNotes = addNotes, username = username)
    
    else:
        if "noteadd" in request.form:
            

            noteBaslik = addNotes.baslik.data
            noteAciklama = addNotes.aciklama.data
            noteOnemSirasi = addNotes.onemSirasi.data


            noteCursor = mysql.connection.cursor()

            noteSorgu = "INSERT INTO notes (username, baslik, aciklama, onemSirasi) VALUES (%s, %s, %s, %s)"
            
            noteCursor.execute(noteSorgu, (session["username"], noteBaslik, noteAciklama, noteOnemSirasi)) 
            
            mysql.connection.commit()
            noteCursor.close()

            noteAddCursor = mysql.connection.cursor()

            noteAddSorgu = "SELECT * FROM notes"

            noteAddCursor.execute(noteAddSorgu)

            noteAddData = noteAddCursor.fetchall()


            flash("Notunuz Kaydedildi!", "success")
            return redirect(url_for("ajandam", username=session["username"], noteAddData = noteAddData)) 
        

        

       


# Kayıt Formu 
class RegisterForm(Form):
    username = StringField(validators=[validators.length(min=5, max=25),validators.InputRequired()])
    email = StringField()
    phone = StringField(validators=[validators.length(min=10, max=10), validators.InputRequired()])
    password = PasswordField(validators=[validators.length(min=8, max=40), validators.InputRequired()])
    passwordAgain = password = PasswordField(validators=[validators.length(min=8, max=40),  validators.InputRequired()])


# Giriş Formu

class LoginForm(Form):
    username = StringField()
    password_entered = PasswordField()


# Not Ekle Formu

class AddNotesForm(Form):
    baslik = StringField()
    aciklama = TextAreaField()
    onemSirasi = StringField(validators=[validators.InputRequired()])



if __name__ == "__main__":
    app.run(debug= True)
 