import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    userID=session["user_id"]
    symbols=db.execute("SELECT symbol FROM stocks WHERE user_id = :userID", userID=userID)
    for symbol in symbols:
        symbolSelect=symbols[0]["symbol"]
        stockDisplays=db.execute("SELECT shares FROM stocks WHERE symbol = :symbolSelect", symbolSelect=symbolSelect)
        for stockDisplay in stockDisplays:
            priceDisplay1=lookup(symbolSelect)
            priceDisplay=(priceDisplay1["price"])
            tStockDisplay=((priceDisplay)*(float(stockDisplays[0]["shares"])))
            cashDisplay=db.execute("SELECT cash FROM users WHERE id = :userID", userID=userID)
            newCash=cashDisplay[0]["cash"]
            usdCash=usd(newCash)
            usdPrice=usd(priceDisplay)
            usdTotal=usd(tStockDisplay)
            return render_template("index.html", symbols=symbols, stockDisplays=stockDisplays, usdPrice=usdPrice, usdTotal=usdTotal, usdCash=usdCash)

    


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "POST":
        symbol=request.form.get("stockSymbol1")
        shares=request.form.get("stockShares")
        stockList=lookup(symbol)
        if stockList == None:
            return apology("invalid symbol", 403)
        elif int(shares) < 1:
            return apology("invalid shares", 403)
        else:
            price=stockList["price"]
            cash=db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"])
            newCash=(cash[0]["cash"]-(price*int(shares)))
            if (newCash < 0):
                return apology("not enough cash")
            else:
                userID=session["user_id"]
                shareOwned=db.execute("SELECT symbol FROM stocks WHERE symbol = :symbol AND user_id = :user_id" , symbol=symbol, user_id=userID)
                if shareOwned == []:
                    db.execute("INSERT INTO stocks ('user_id', 'symbol', 'shares') VALUES(:userID, :symbol, :shares)", userID=userID, symbol=symbol, shares=shares) 
                    db.execute("UPDATE users SET cash = :newCash WHERE id = :user_id", newCash=newCash, user_id=session["user_id"])
                    return redirect("/")
                else:
                    oldShares=db.execute("SELECT shares FROM stocks WHERE symbol = :symbol AND user_id = :user_id", symbol=symbol, user_id=userID)
                    newShares=(int(oldShares[0]["shares"])+int(shares))
                    db.execute("UPDATE stocks SET shares = :newShares WHERE user_id = :user_id AND symbol = :symbol", user_id=userID, symbol=symbol, newShares=newShares)
                    db.execute("UPDATE users SET cash = :newCash WHERE id = :user_id", newCash=newCash, user_id=session["user_id"])
                    return redirect("/")
                        
    else:
        return render_template("buy.html")
        
        
    
    """Buy shares of stock"""

   
    


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    if request.method == "POST":    
        stockList=lookup(request.form.get("stockSymbol"))
        if stockList == None:
            return apology("invalid stock symbol", 403)
        else:
            stockPrice=stockList["price"]
            usdPrice=usd(stockPrice)
            return render_template("quoted.html", stockList=stockList, usdPrice=usdPrice)
            
            
                                       
    else:
        return render_template("quote.html")
    """Get stock quote."""
@app.route("/change", methods=["GET", "POST"])
def change():
    if request.method == "POST":
           password=request.form.get("password")
           passwordNew=request.form.get("passwordNew")
           passwordConfirm=request.form.get("passwordConfirm")
           hashConfirmation=db.execute("SELECT hash FROM users WHERE id = :userID", userID=session["user_id"])
           userHash=generate_password_hash(password)                             
           if not password or not passwordNew:
               return apology("invalid username and/or password", 403)
           elif (passwordConfirm != passwordNew):
               return apology("password and confirmation do not match", 403)
           elif (userHash != (hashConfirmation[0]["hash"])):
               return apology("password is wrong", 403)                                       
           else:
               db.execute("UPDATE users SET hash = :userHash WHERE id = :userID", userHash=userHash, userID=session["user_id"])
               return redirect("/login")
    else:
        return render_template("change.html")



@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username=request.form.get("username")
        password=request.form.get("password")
        confirmation=request.form.get("confirmation")
        if not username or not password:  
            return apology("invalid username and/or password", 403)
        if (confirmation != password):
            return apology("password and confirmation do not match", 403)
        usernameValidation=db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))
        if (len(usernameValidation) > 0):
            return apology("username is taken", 403)
        else:
            userHash = generate_password_hash(password)
            newUser = db.execute("INSERT INTO users ('username', 'hash') VALUES(:username, :userHash)", username=username, userHash=userHash)
            return redirect("/login")
    else:
        return render_template("register.html")
    """Register user"""
 


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        symbolInfo = lookup(request.form.get("symbol"))
        if symbolInfo == None:
            return apology("invalid symbol")
        try:
            shares = int(request.form.get("shares"))
        except:
            return apology("must be a number")
        if shares < 0:
            return apology("input positive number")
        sharesOwned = db.execute("SELECT shares FROM stocks WHERE user_id = :user_id AND symbol = :symbol", user_id=session["user_id"], symbol=request.form.get("symbol"))

        if sharesOwned[0]["shares"] < 1 or shares > sharesOwned[0]["shares"]:
            return apology("not enough shares")
        price = symbolInfo["price"]
        totalPrice = shares * price
        db.execute("UPDATE users SET cash = cash + :totalPrice WHERE id = :user_id", user_id=session["user_id"], totalPrice=totalPrice)
        db.execute("INSERT INTO stocks (user_id, symbol, shares) VALUES(:user_id, :symbol, :shares)", user_id=session["user_id"], symbol=request.form.get("symbol"), shares=shares)

        return redirect("/")

    else:
        sharesOwned = db.execute("SELECT symbol, shares FROM stocks WHERE user_id = :user_id", user_id=session["user_id"])
        return render_template("sell.html", sharesOwned=sharesOwned)

    


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
