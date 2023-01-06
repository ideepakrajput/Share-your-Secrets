require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption");
const _ = require("lodash");

const app = express();

app.set("view engine", "ejs");

app.use(bodyParser.urlencoded({ extended: true }));

app.use(express.static("public"));

mongoose.set('strictQuery', true);
mongoose.connect("mongodb://127.0.0.1:27017/UserDB");

const userSchema = new mongoose.Schema({
    username: String,
    password: String
});

userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ['password'] });

const User = mongoose.model("User", userSchema);

app.get("/", function (req, res) {
    res.render("home");
});

app.get("/login", function (req, res) {
    res.render("login");
});

app.post("/login", function (req, res) {
    const enteredUsername = req.body.username;
    const enteredPassword = req.body.password;

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
});

app.get("/register", function (req, res) {
    res.render("register");
});

app.post("/register", function (req, res) {
    const newUser = new User({
        username: req.body.username,
        password: req.body.password
    });

    newUser.save(function (err) {
        if (err) {
            console.log(err);
        } else {
            res.render("secrets");
        }
    });
});

app.listen(3000, function () {
    console.log("Server running on port 3000");
})