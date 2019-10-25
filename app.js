//jshint esversion:6

require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const TwitterStrategy = require('passport-twitter').Strategy;
const findOrCreate = require('mongoose-findorcreate');

// const bcrypt = require('bcrypt');
// const saltRounds = 10;

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: "little secret.",
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());


mongoose.connect("mongodb://localhost:27017/userDB", { useNewUrlParser: true, useUnifiedTopology: true });
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    facebookId: String,
    twitterId: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());
passport.serializeUser(function (user, done) {
    done(null, user.id);
});

passport.deserializeUser(function (id, done) {
    User.findById(id, function (err, user) {
        done(err, user);
    });
});

/// GOOGLE LOGIN ///
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
    function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({ googleId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));

/// FACEBOOK LOGIN ///
passport.use(new FacebookStrategy({
    clientID: process.env.APP_ID,
    clientSecret: process.env.APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
},
    function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({ facebookId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));

/// TWITTER LOGIN ///
passport.use(new TwitterStrategy({
    consumerKey: process.env.CONSUMER_KEY,
    consumerSecret: process.env.CONSUMER_SECRET,
    callbackURL: "http://127.0.0.1:3000/auth/twitter/callback"
},
    function (token, tokenSecret, profile, cb) {
        User.findOrCreate({ twitterId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));


app.get("/", (req, res) => {

    res.render("home");
});


/// GOOGLE LOGIN SIDE ///
app.get("/auth/google",
    passport.authenticate("google", { scope: ["profile"] })
);

app.get('/auth/google/secrets',
    passport.authenticate('google', { failureRedirect: "/login" }),
    function (req, res) {
        res.redirect('/secrets');
    });


/// FACEBOOK LOGIN SIDE ///
app.get("/auth/facebook",
    passport.authenticate("facebook")
);

app.get('/auth/facebook/secrets',
    passport.authenticate('facebook', { failureRedirect: "/login" }),
    function (req, res) {
        res.redirect('/secrets');
    });


/// TWITTER LOGIN SIDE ///
app.get("/auth/twitter",
    passport.authenticate("twitter")
);

app.get('/auth/twitter/secrets',
    passport.authenticate('twitter', { failureRedirect: "/login" }),
    function (req, res) {
        res.redirect('/secrets');
    });


/// LOGIN PAGE///////////////////////////////////////////
app.route("/login")
    .get((req, res) => {
        res.render("login");
    })
    .post((req, res) => {
        const user = new User({
            username: req.body.username,
            password: req.body.password
        });
        req.login(user, (err) => {
            if (!err) {
                passport.authenticate("local", { failureRedirect: '/login' })(req, res, () => {
                    res.redirect("/secrets");
                });
            } else {
                res.status(401).send();
            }
        });
        // const username = req.body.username;
        // const password = req.body.password;

        // User.findOne({ email: username }, function (err, foundUser) {
        //     if (err) {
        //         console.log(err);
        //     } else {
        //         if (foundUser) {
        //             bcrypt.compare(password, foundUser.password, function (err, result) {
        //                 if (result) {
        //                     res.render("secrets");
        //                 }
        //             });
        //         }
        //     }
        // });
    });

app.get("/secrets", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("secrets");
    } else {
        res.redirect("/login");
    }
});

app.get("/logout", (req, res) => {
    req.logout();
    res.redirect("/");
});

app.route("/submit")
    .get((req, res) => {
        if (req.isAuthenticated()) {
            res.render("submit");
        } else {
            res.redirect("/login");
        }
    })
    .post((req, res) => {

    });


/// REGISTER PAGE ////////////////////////////////////
app.route("/register")
    .get((req, res) => {

        res.render("register");
    })
    .post((req, res) => {
        User.register({ username: req.body.username }, req.body.password, (err, user) => {
            if (err) {
                res.redirect("/register");
            } else {
                passport.authenticate("local")(req, res, () => {
                    res.redirect("/secrets");
                });
            }
        });
        // bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
        //     const newUser = new User({
        //         email: req.body.username,
        //         password: hash
        //     });
        //     newUser.save()
        //         .then(() => res.render("secrets"))
        //         .catch(() => { res.status(400).send(); });
        // });

    });

let port = process.env.PORT;
if (port == null || port == "") {
    port = 3000;
}

app.listen(port, function () {
    console.log("Server has started.");
});