const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const User = require('./models/user');
const JwtStrategy = require('passport-jwt').Strategy; //constructor
const ExtractJwt = require('passport-jwt').ExtractJwt; //object that will provide us with several helper methods
//one of which we'll use later to extract jw token from a req obj
const jwt = require('jsonwebtoken'); // used to create, sign, and verify tokens

const config = require('./config.js');

exports.local = passport.use(new LocalStrategy(User.authenticate()));
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());


exports.getToken = function(user) {
    return jwt.sign(user, config.secretKey, {expiresIn: 3600});
};

//configure jwt strategy for passport - opts is options
const opts = {};
//using one of the helper methods from extractjwt - specifies how JWT should be extracted - simplest method
opts.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
//lets us supply jwt strategy with a key with which we'll assign the token
opts.secretOrKey = config.secretKey;

//exporting jwt strategy
exports.jwtPassport = passport.use(
    new JwtStrategy(
        opts,
        (jwt_payload, done) => {
            console.log('JWT payload:', jwt_payload);
            User.findOne({_id: jwt_payload._id}, (err, user) => {
                if (err) {
                    //(error?, user?)
                    return done(err, false);
                } else if (user) {
                    return done(null, user);
                } else {
                    return done(null, false);
                }
            });
        }
    )
);

//verify that an incoming request is from a user - using jwt strategy, not sessions
//setting it up here to use in other modules whenever we want to authenticate w/ JWT
exports.verifyUser = passport.authenticate('jwt', {session: false});