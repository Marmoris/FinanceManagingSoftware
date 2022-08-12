#Imports
from flask import Flask, render_template, url_for, redirect, g, session, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from wtforms.widgets import TextArea
from flask_bcrypt import Bcrypt
from datetime import datetime

#Prep stuff
app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://kuvbispuxfbmdx:893603aafcf166d13ef0dd28e610d2e12e4368658eb76867195bbe7e2d06f408@ec2-3-219-229-143.compute-1.amazonaws.com:5432/d6cprjq42518ki'
app.config['SECRET_KEY'] = 'thisisasecretkey'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    dropDownText = db.Column(db.Text)
    totalMoney = db.Column(db.REAL, nullable=False)

class BudgetChange(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    wami = db.Column(db.String(500), default = "")
    date = db.Column(db.Date, default = datetime.utcnow)
    description = db.Column(db.String(300))
    amount = db.Column(db.REAL, nullable = False)

    def __repr__(self):
        return '<BudgetChange %r>' % self.id

class SectionBudget(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    wami = db.Column(db.String(500), default = "", unique = True)
    amount = db.Column(db.REAL, nullable = False)

    def __repr__(self):
        return "<SectionBudget %r>" % self.id



class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')


    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError('That username already exists. Please choose a different one.')

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')

class DropdownForm(FlaskForm):
    body = StringField('Body', widget = TextArea())
    submit = SubmitField('Submit')

# My functions and related stuff

def makeDict(f):
    f = f.split("\n")
    for i in range(0, len(f)):
        f[i] = f[i].split('(')
        for j in range(0, len(f[i])):
            f[i][j] = f[i][j].replace(")", "")
            f[i][j] = f[i][j].replace("\r", "")
        if '' in f[i]:
            f[i].remove('')

    while [] in f:
        f.remove([])
    
    dictionary = {}
    for new in f:
        temps = [dictionary]
        for i in new[:-1]:
            temps.append(temps[-1][i])

        temps[-1][new[-1]]={}
        dictionary = temps[0]

    return dictionary

def getList(dictionary, choices):
    tempChoices = []
    out = []
    for i in range(0,len(choices)+1):
        temps = [dictionary]
        for choice in tempChoices:
            temps.append(temps[-1][choice])

        out.append(list(temps[-1].keys()))

        if i<len(choices):
            tempChoices.append(choices[i])

    return out

def getPlacement(text):
    text = text.split("]")
    for i in range(0, len(text)):
        text[i] = text[i].split("[")

    return int(text[0][-1])

def fixChoices(choices): #set choices = fixChoices(choices)
    out = []
    if choices == [] or getPlacement(choices[-1])>=len(choices):
        return choices
    else:
        for i in range(0, len(choices)-1):
            if getPlacement(choices[i])<getPlacement(choices[-1]):
                out.append(choices[i])

        out.append(choices[-1])

        return out

def makeRightOrder(choices, selection):
    try:
        at = choices.index(selection)
        out = [selection]
        for i in range(0, len(choices)):
            if i != at:
                out.append(choices[i])

        return out
    except:
        return choices

def createWami(choices):
    wami = ""
    for i in choices:
        wami = wami  + "~" + i

    return wami

def checkInWami(choices, wami):
    wami = wami.split("~")[1:]

    for choice in choices:
        if choice not in wami:
            return False

    return True

def calculateTotal(changes, currUser):
    out = 0
    for change in changes:
        if change.user_id == currUser and checkInWami(session["choices"], change.wami):
            out+=change.amount

    return out

def calculateAverage(changes, currUser):
    out = 0
    num = 0
    for change in changes:
        if change.user_id == currUser and checkInWami(session["choices"], change.wami):
            out+=change.amount
            num+=1

    if num == 0:
        return "-"
    return float(out)/num

def getLargest(changes, currUser):
    largestValue = -139200000000
    largestDate = None
    for change in changes:
        if change.user_id == currUser and checkInWami(session["choices"], change.wami):
            if change.amount > largestValue:
                largestValue = change.amount
                largestDate = change.date

    if largestDate == None:
        return [0,"-"]

    return [largestValue, largestDate]

def getSmallest(changes, currUser):
    smallestValue = 139200000000
    smallestDate = None
    for change in changes:
        if change.user_id == currUser and checkInWami(session["choices"], change.wami):
            if change.amount < smallestValue:
                smallestValue = change.amount
                smallestDate = change.date

    if smallestDate == None:
        return [0,"-"]

    return [smallestValue, smallestDate]

def checkSectionsFormat(sections):
    sections = sections.split("\n")

    for k in range(0, len(sections)-1):
        sections[k] = sections[k][:-1]

    for i in sections:
        if i != "" and sections.count(i)>1:
            return False 

    for i in sections:
        temp = i.split("(")
        if temp[0]!="":
            return False
        
        for j in temp[1:]:
            if j.count(")") != 1:
                return False

        temp2 = i.split("[")
        if temp2[0]!="(" and temp2[0]!="":
            return False

        for j in temp2[1:]:
            if j.count("]") != 1:
                return False

        temp3 = i.split("{")
        if len(temp3)>2:
            return False

        if len(temp3) == 2 and temp3[-1].count("}") != 1:
            return False

        temp4 = i.split(")")
        if temp4[-1]!="":
            return False

        for j in temp4[:-1]:
            if j.count("(") != 1:
                return False

        temp5 = i.split("]")
    
        for j in temp5[:-1]:
            if j.count("[") != 1:
                return False

        temp6 = i.split("}")
        
        if len(temp6)>2:
            return False
        
        if len(temp6) == 2 and temp6[0].count("{") != 1:
            return False
    return True

def getSectionText(sect):
    if "{" in sect:
        return sect[3:sect.index("{")]
    return sect[3:]

def getSectionType(wami):
    wami = wami.split("~")
    current = wami[-1].split("{")[-1].split("}")[0]
    return current

def wamiStillExists(wami, dropDownDict):
    wami = wami.split("~")[1:]
    currentDict = dropDownDict
    for i in wami:
        if i in currentDict:
            currentDict = currentDict[i]
        else:
            return False

    return True

def getAllWamis(allBudgets):
    out = []
    for i in allBudgets:
        out.append(i.wami)

    return out

#Page building:

@app.before_request
def before_request():
    if current_user.is_authenticated:
        g.user = current_user.username

        text = User.query.filter_by(username=g.user).first().dropDownText
        g.dropDownDict = makeDict(text)

        myUser = User.query.filter_by(username=g.user).first()
        allData = BudgetChange.query.filter_by(user_id = current_user.id).all()

        total = 0
        for element in allData:
            if getSectionType(element.wami) == "E":
                total -= element.amount
            elif getSectionType(element.wami) == "I":
                total += element.amount
        myUser.totalMoney = total

        allData = BudgetChange.query.filter_by(user_id = current_user.id).all()

        for element in allData:
            if wamiStillExists(element.wami, g.dropDownDict) == False:
                change_to_delete = BudgetChange.query.get_or_404(element.id)
                try:
                    db.session.delete(change_to_delete)
                    db.session.commit()
                except:
                    return "There was an issue with your request. Please try again or contact the software company for assistance."
        


@app.route('/', methods = ['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                session["choices"] = []
                return redirect(url_for('dashboard'))
            else:
                flash("Your password is incorrect. Please try again.", "warning")
        else:
            flash("Your username could not be identified. Please try again.", "warning")
    
    return render_template('login.html', form = form)

@app.route('/dashboard', methods = ['GET', 'POST'])
@login_required
def dashboard():
    allBudgets = SectionBudget.query.all()
    myUser = User.query.filter_by(username=g.user).first()

    if session.get("choices") is None:
        session["choices"] = []
    
    if request.method == "POST":
        if "content" in request.form:
            addition_content = request.form["content"]
            
            if request.form["amount"] == "":
                flash("Value entered is not valid. Please try again.")
            else:
                addition_amount = float(request.form["amount"])
                new_addition = BudgetChange(description = addition_content, amount = addition_amount, user_id = current_user.id, wami = createWami(session["choices"])) #date, description, amount

                try:
                    db.session.add(new_addition)
                    db.session.commit()
                    return redirect("/dashboard")
                except:
                    return "There was an issue with your request. Please try again or contact the software company for assistance."
        elif "budgetAmount" in request.form:
            budgetAmount = request.form["budgetAmount"]
            new_budget = SectionBudget(wami = createWami(session["choices"]), amount = budgetAmount)
            
            if request.form["budgetAmount"] == "":
                flash("Value entered is not valid. Please try again.")
            else:
                try:
                    db.session.add(new_budget)
                    db.session.commit()
                    return redirect("/dashboard")
                except:
                    return "There was an issue with your request. Please try again or contact the software company for assistance."
            
        else:
            temp = session['choices']
            text = request.form.get("dropDownChoice")
            temp.append(text)
            temp = fixChoices(temp)
            session['choices'] = temp
            return redirect(url_for("dashboard"))

        return render_template('dashboard.html', dictionary = g.dropDownDict, getList = getList, makeRightOrder = makeRightOrder, getPlacement = getPlacement, changes = "", currUser = current_user.id, checkInWami = checkInWami, calculateTotal = calculateTotal, calculateAverage=calculateAverage, getLargest=getLargest, getSmallest=getSmallest, myUser=myUser, getSectionText=getSectionText, getSectionType=getSectionType, createWami=createWami, allBudgets = allBudgets, getAllWamis=getAllWamis)
    else:
        changes = BudgetChange.query.order_by(BudgetChange.date).all()
        return render_template('dashboard.html', dictionary = g.dropDownDict, getList = getList, makeRightOrder = makeRightOrder, getPlacement = getPlacement, changes = changes, currUser = current_user.id, checkInWami = checkInWami, calculateTotal=calculateTotal, calculateAverage=calculateAverage, getLargest=getLargest, getSmallest=getSmallest,myUser=myUser, getSectionText=getSectionText, getSectionType=getSectionType, createWami=createWami, allBudgets = allBudgets, getAllWamis=getAllWamis)

@app.route("/delete/<int:id>")
@login_required
def delete(id):
    change_to_delete = BudgetChange.query.get_or_404(id)

    try:
        db.session.delete(change_to_delete)
        db.session.commit()
        return redirect("/dashboard")
    except:
        return "There was an issue with your request. Please try again or contact the software company for assistance."

@app.route("/deleteBudget/<int:id>")
@login_required
def deleteBudget(id):
    budget_to_delete = SectionBudget.query.get_or_404(id)
    try:
        db.session.delete(budget_to_delete)
        db.session.commit()
        return redirect("/dashboard")
    except:
        return "There was an issue with your request. Please try again or contact the software company for assistance."


@app.route("/update/<int:id>", methods = ["GET", "POST"])
@login_required
def update(id):
    change = BudgetChange.query.get_or_404(id)
    if request.method == "POST":
        change.description = request.form["content"]
        change.amount = request.form["amount"]

        try:
            db.session.commit()
            return redirect("/dashboard")
        except:
            return "There was an issue with your request. Please try again or contact the software company for assistance."
    else:
        return render_template("update.html", change = change)

@app.route("/updateBudget/<int:id>", methods = ["GET", "POST"])
def updateBudget(id):
    allBudgets = SectionBudget.query.all()
    budget = SectionBudget.query.get_or_404(id)

    if request.method == "POST":
        budget.amount = request.form["amount"]

        try:
            db.session.commit()
            return redirect("/dashboard")
        except:
            return "There was an issue with your request. Please try again or contact the software company for assistance."
    else:
        return render_template("updateBudget.html", budget = budget, createWami=createWami, allBudgets = allBudgets, getAllWamis=getAllWamis)

@app.route('/logout', methods = ['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route("/allData")
@login_required
def allData():
    session["choices"] = []
    return redirect(url_for("dashboard"))


@app.route('/settings', methods = ['GET', 'POST'])
@login_required
def settings():
    form = DropdownForm()
    myUser = User.query.filter_by(username=g.user).first()

    if form.validate_on_submit():
        try:
            if not checkSectionsFormat(form.body.data):
                flash("The format of your section input is incorrect. Please try again.")
            else:
                test = makeDict(form.body.data)
                myUser.dropDownText = form.body.data
                text = User.query.filter_by(username=g.user).first().dropDownText
                db.session.commit()
                session["choices"] = []
                
        except:
            flash("The format of your section input is incorrect. Please try again.")

    return render_template('settings.html', form=form, myUser = myUser, getList = getList)

@app.route('/confirm', methods = ["GET", "POST"])
@login_required
def confirm():
    return render_template("confirm.html")

@app.route('/confirmReset', methods = ["GET", "POST"])
@login_required
def confirmReset():
    return render_template("confirmReset.html")

@app.route('/deleteUser/<int:id>')
@login_required
def deleteUser(id):
    user_to_delete = User.query.get_or_404(id)
    query = db.session.query(BudgetChange).filter_by(user_id = id).all()

    try:
        for change in query:
            db.session.delete(change)
            db.session.commit()
    except:
        return "There was an issue with your request. Please try again or contact the software company for assistance."

    try: 
        db.session.delete(user_to_delete)
        db.session.commit()
    except: 
        return "There was an issue with your request. Please try again or contact the software company for assistance."
    
    return redirect("/")

@app.route('/resetData/<int:id>')
@login_required
def resetData(id):
    query = db.session.query(BudgetChange).filter_by(user_id = id).all()

    try:
        for change in query:
            db.session.delete(change)
            db.session.commit()
    except:
        return "There was an issue with your request. Please try again or contact the software company for assistance."

    return redirect(url_for("dashboard"))


@app.route('/register', methods = ['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password, dropDownText="", totalMoney = 0)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form = form)


if __name__ == '__main__':
    app.run(debug=True)