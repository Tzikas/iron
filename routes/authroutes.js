const express    = require('express');
const authRoutes = express.Router();

const passport   = require('passport');
const bcrypt     = require('bcryptjs');

// the user model
const User       = require('../models/user');



authRoutes.post('/signup', (req, res, next) => {
    console.log(req.body)
    const username = req.body.username;
    const password = req.body.password;
  
    if (!username || !password) {
      res.status(400).json({ message: 'Provide username and password' });
      return;
    }

    if(password.length < 7){
        res.status(400).json({ message: 'Please make your password at least 7 characters long for secutiry purposes.' });
        return;
    }
  
    User.findOne({ username }, '_id', (err, foundUser) => {
      if (foundUser) {
        res.status(400).json({ message: 'The username already exists' });
        return;
      }
  
      const salt     = bcrypt.genSaltSync(10);
      const hashPass = bcrypt.hashSync(password, salt);
  
      const theUser = new User({
        username:username,
        password: hashPass
      });
  
      theUser.save((err) => {
        if (err) {
          res.status(400).json({ message: 'Something went wrong saving user to Database' });
          return;
        }
  
        req.login(theUser, (err) => {
          if (err) {
            res.status(500).json({ message: 'Something went wrong' });
            return;
          }
  
          res.status(200).json(req.user);
        });
        });
      });
    });



    authRoutes.post('/login', (req, res, next) => {
        console.log(req.body)
    
        passport.authenticate('local', (err, theUser, failureDetails) => {
          if (err) {
            res.status(500).json({ message: 'Something went wrong authenticating user' });
            return;
          }
      
          if (!theUser) {
            res.status(401).json(failureDetails);
            return;
          }
      
          req.login(theUser, (err) => {
            if (err) {
              res.status(500).json({ message: 'Something went wrong' });
              return;
            }
      
            // We are now logged in (notice req.user)
            console.log(req.user, ' logged in')
            res.status(200).json(req.user);
          });
        })(req, res, next);
      });



      authRoutes.post('/logout', (req, res, next) => {
        req.logout();
        console.log(req.user, ' logged out')

        res.status(200).json({ message: 'Success' });
      });

   


      authRoutes.get('/loggedin', (req, res, next) => {
        console.log(req.user, ' loggedin2')
      
        if (req.user) {
          res.status(200).json(req.user);
          return;
        }
        res.status(403).json({ message: 'Unauthorized' });
      });
















module.exports = authRoutes;


