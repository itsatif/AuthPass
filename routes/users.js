const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport');


//User model
const User = require('../models/Users')

//login 
router.get('/login',(req,res) => res.render("login"));

// Registration page
router.get('/register',(req, res) => res.render('register'));

//Registration Handle
router.post('/register', (req,res) => {
    const {name, email, password, password2 } = req.body;
    let errors = [];

    //check required fields
    if(!name || !email || !password || !password2){
        errors.push({msg : 'Passwords do not match'});
    }
    //Check pass length
    if(password.length < 8){
        errors.push({msg : 'Password should be atleast 8 Characters'});
    }

    if(errors.length > 0){
        res.render('register', {
            errors,
            name,
            email,
            password,
            password2
          });
    }else{
        // Validation passed
        User.findOne({email: email })
           .then(user => {
               if(user) {
                      //User exists
                      errors.push({ msg: 'Email is already registered' });
                      res.render('register', {
                        errors,
                        name,
                        email,
                        password,
                        password2
                      });
               }else{
                     const newUser = new User({
                         name,
                         email,
                         password
                     });

                    
                     //Hash Password
                     bcrypt.genSalt(10, (err, salt) => bcrypt.hash(newUser.password, salt, (err, hash) => {
                        if(err) throw err;
                        // Set password to hashed
                        newUser.password = hash;
                        //Save user
                        newUser.save()
                          .then(user => {
                              req.flash('succes_msg','You are now registered');
                              res.redirect('/users/login');
                          })
                          .catch(err => console.log(err))
                     }));
               }
           })
    }
});

//login handle
router.post('/login', (req,res,next) => {
  passport.authenticate('local',{
      successRedirect: '/dashboard',
      failureRedirect: '/users/login',
      failureFlash: true
  })(req, res, next);
});

//logout handle
router.get('/logout',(req,res) => {
    req.logout();
    req.flash('sucess_msg', 'You are logged out');
    res.redirect('/users/login');
})

module.exports = router;