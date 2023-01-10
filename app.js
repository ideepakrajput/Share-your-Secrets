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
const LocalStrategy = require('passport-local');
const passportLocalMongoose = require("passport-local-mongoose");
const saltRounds = 10;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const https = require("https");
const { response } = require('express');

let notSamePassword;
let invalidEmail;
let isUserFound;

const app = express();

app.set("view engine", "ejs");

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(session({
    secret: process.env.secretSession,
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.set('strictQuery', true);
mongoose.connect("mongodb+srv://admin-secrets:Deepak-3354@cluster0.ym9apxb.mongodb.net/UserDB");

const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    googleId: String,
    facebookId: String,
    secrets: []
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);

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

//Google OAuth2.0
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "https://secrets-deepak.onrender.com/auth/google/secrets"
},
    function (accessToken, refreshToken, profile, cb) {
        console.log(profile);
        User.findOrCreate({ googleId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));

app.get("/auth/google",
    passport.authenticate("google", { scope: ["profile"] })
);

app.get("/auth/google/secrets",
    passport.authenticate("google", { failureRedirect: "/login" }),
    function (req, res) {
        res.redirect("/secrets");
    }
);

//Facebook OAuth2.0
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "https://secrets-deepak.onrender.com/auth/facebook/secrets",
    enableProof: true,
    profileFields: ['id', 'displayName', 'photos', 'email']
},
    function (accessToken, refreshToken, profile, cb) {
        console.log(profile);
        User.findOrCreate({ facebookId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    })
);

app.get("/auth/facebook",
    passport.authenticate("facebook")
);

app.get("/auth/facebook/secrets",
    passport.authenticate("facebook", { failureRedirect: "/login" }),
    function (req, res) {
        res.redirect("/secrets");
    }
);

// Home Route
app.get("/", function (req, res) {
    res.render("home");
});

//Register Route
app.route("/register")
    .get((req, res) => {
        res.render("register");
    })
    .post((req, res) => {
        const api_key = process.env.api_key;
        const email = req.body.username;
        const password = req.body.password;
        const confirmPassword = req.body.confirmPassword;
        const url = "https://api.zerobounce.net/v2/validate?email=" + email + "&api_key=" + api_key;
        https.get(url, (response) => {
            response.on("data", (data) => {
                const responseData = JSON.parse(data);
                const emailStatus = responseData.status;
                const ranOutCredits = responseData.error;
                if (password === confirmPassword) {
                    if (emailStatus === "valid" || ranOutCredits === "Invalid API key or your account ran out of credits") {
                        User.findOne({ username: email }, (err, user) => {
                            if (user === null) {
                                User.register({ username: req.body.username }, req.body.password, (err, user) => {
                                    if (err) {
                                        console.log(err);
                                        res.render("/register");
                                    } else {
                                        passport.authenticate("local")(req, res, () => {
                                            res.redirect("/secrets");
                                        })
                                    }
                                })
                            } else {
                                isUserFound = false;
                                res.redirect("/error");
                            }
                        })
                    } else {
                        invalidEmail = true;
                        res.redirect("/error");
                    }
                } else {
                    notSamePassword = true;
                    res.redirect("/error");
                }
            })
        })
    })

//Login Route
app.route("/login")
    .get((req, res) => {
        res.render("login");
    })
    .post((req, res) => {
        const user = new User({
            username: req.body.username,
            password: req.body.password
        });
        User.findOne({ username: user.username, password: user.password }, (err, foundUser) => {
            if (err) {
                isUserFound = false;
                res.redirect("/error");
            } else {
                req.login(user, (err) => {
                    if (err) {
                        isUserFound = false;
                        res.redirect("/error");
                    } else {
                        passport.authenticate("local")(req, res, () => {
                            res.redirect("/secrets");
                        })
                    }
                });
            }
        })
    })

//Logout Route
app.get("/logout", function (req, res) {
    req.logout(function (err) {
        if (err) {
            console.log(err);
        }
        res.redirect('/');
    });
});

//Submit Route
app.route("/submit")
    .get((req, res) => {
        if (req.isAuthenticated()) {
            res.render("submit");
        } else {
            res.redirect("/login");
        }
    })
    .post((req, res) => {
        const submittedSecret = req.body.secret;
        User.findById(req.user.id, (err, foundUser) => {
            if (err) {
                isUserFound = false;
                res.redirect("/error");
                console.log(err);
            } else if (foundUser === null) {
                isUserFound = false;
                res.redirect("/error");
            } else {
                foundUser.secrets.push(submittedSecret);
                foundUser.save(function () {
                    res.redirect("/secrets");
                });
            }
        })
    })

//Secrets Route    
app.get("/secrets", (req, res) => {
    User.find({ "secrets": { $ne: null } }, (err, foundUsers) => {
        if (err) {
            console.log(err);
        } else {
            res.render("secrets", { usersWithSecrets: foundUsers });
        }
    })
});

//Error Route
app.get("/error", (req, res) => {
    res.render("error", { notSamePassword: notSamePassword, invalidEmail: invalidEmail, isUserFound: isUserFound });
});

//Delete Route
app.post("/delete" ,(req,res)=>{
    const selectedSecret=req.body.selectedSecret;

    User.findOneAndRemove({secerts:selectedSecret},(err,foundSecret)=>{
        if (err) {
            res.redirect("/error");
        } else {
            res.redirect("/secrets");
        }
    })
})

app.listen(process.env.PORT || 3000);