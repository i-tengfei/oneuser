var mongoose = require('mongoose');

var UserModel = mongoose.model('user'),
    ClientModel = mongoose.model('client');

module.exports = function(app, passport){

    app.post('/auth', function(req, res){
        if (req.isAuthenticated()) return res.send(req.user);
        res.status(401).end();
    });

    app.all('/logout', function(req, res){
        req.logout();
        res.redirect('/');
    });

    app.get('/signup', function(req, res) {
        res.render('signup.jade');
    });

    app.post('/signup', function(req, res) {
        var user = new UserModel(req.body);
        user.save(function (err, result) {
            if(err) return res.status(500).send(err);
            res.send(result);
        });
    });

    app.get('/login', function(req, res) {
        if(req.isAuthenticated()) return res.writeHead(303, {Location: '/'}).end();
        res.render('login.jade', {
            next_url: req.query.next ? req.query.next : '/'
        });
    });

    app.post('/login', function(req, res, next) {
        passport.authenticate('local', function(err, user, info) {
            if(err) return res.status(500).send(err);
            if(user) return req.login(user, function(){
                res.writeHead(303, {Location: req.body.next || '/'}).end();
            });
            res.status(401).end();
        })(req, res, next);
    });

    app.get('/user', function(req, res, next) {
        if(req.isAuthenticated()) return res.send(req.user);
        res.status(401).end();
    });

    app.get('/client', function(req, res, next) {

        if(!req.isAuthenticated()) return res.status(401).end();
        var client = new ClientModel({
            user: req.user._id
        });
        client.save(function(err, result){
            if(err) return res.status(500).send(err);
            res.send(result);
        });
    });

};

