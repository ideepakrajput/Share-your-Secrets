require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption");
const _ = require("lodash");
const md5 = require("md5");
const bcrypt = require("bcrypt");
const session = require("express-session");
const passport = require("passport");
var LocalStrategy = require('passport-local');
const passportLocalMongoose = require("passport-local-mongoose");
const saltRounds = 10;
var GoogleStrategy = require('passport-google-oauth20').Strategy;
var findOrCreate = require('mongoose-findorcreate');

const app = express();

app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(session({
    secret: process.env.secretSession,
    resave: false,
    saveUninitialized: false
    // cookie: { secure: true }
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.set('strictQuery', true);
mongoose.connect("mongodb://127.0.0.1:27017/UserDB");

const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    googleId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ['password'] });

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());
/* passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser()); */

passport.serializeUser(function (user, cb) {
    process.nextTick(function () {
        return cb(null, {
            id: user.id,
            username: user.username,
            picture: user.picture
        });
    });
});

passport.deserializeUser(function (user, cb) {
    process.nextTick(function () {
        return cb(null, user);
    });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
},
    function (accessToken, refreshToken, profile, cb) {
        console.log(profile);
        User.findOrCreate({ googleId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));

app.get("/", function (req, res) {
    res.render("home");
});

app.get("/login", function (req, res) {
    res.render("login");
});

app.post("/login", function (req, res) {
    /* For Before Using Session
    const enteredUsername = req.body.username;
    //const enteredPassword: req.body.password      //for mongoose-encryption and plugin
    const enteredPassword = md5(req.body.password)      //for hash function

    User.findOne({ username: enteredUsername }, function (err, foundUser) {
        if (err) {
            res.render("error");
        } else {
            if (foundUser.password === enteredPassword) {
                res.render("secrets");
            }
            else {
                res.render("error");
            }
        }
    }); 
    */
    // After using session and cookies
    const user = new User({
        username: req.body.username,
        password: req.body.password
    })

    req.login(user, function (err) {
        if (err) {
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets");
            })
        }
    })

});

app.get("/register", function (req, res) {
    res.render("register");
});

app.get("/secrets", function (req, res) {
    User.find({ "secret": { $ne: null } }, function (err, foundUsers) {
        if (err) {
            console.log(err);
        } else {
            res.render("secrets", { usersWithSecrets: foundUsers });
        }
    })
})

app.post("/register", function (req, res) {
    /* Before Using Session and cookies
    bcrypt.hash(req.body.password, saltRounds, function (err, hash) {       //for bcrypt
        const newUser = new User({
            username: req.body.username,
            // password: req.body.password              //for mongoose-encryption and plugin
            // password: md5(req.body.password)         //for hash function
            password: hash                              //for bcrypt
        });

        newUser.save(function (err) {
            if (err) {
                console.log(err);
            } else {
                res.render("secrets");
            }
        });
    }); 
    */
    // After using session and cookies
    User.register({ username: req.body.username }, req.body.password, function (err, user) {
        if (err) {
            console.log(err);
            res.render("/register");
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets");
            })
        }
    })
});

app.get("/logout", function (req, res) {
    req.logout(function (err) {
        if (err) {
            console.log(err);
        }
        res.redirect('/');
    });
});

app.get("/auth/google",
    passport.authenticate("google", { scope: ["profile"] })
);

app.get("/auth/google/secrets",
    passport.authenticate("google", { failureRedirect: "/login" }),
    function (req, res) {
        res.redirect("/secrets");
    }
);

app.get("/submit", function (req, res) {
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }
})

app.post("/submit", function (req, res) {
    const submittedSecret = req.body.secret;

    User.findById(req.user.id, function (err, foundUser) {
        if (err) {
            console.log(err);
        } else {
            foundUser.secret = submittedSecret;
            foundUser.save(function () {
                res.redirect("/secrets");
            });
        }
    })
})

app.listen(3000, function () {
    console.log("Server running on port 3000");
})