var mongoose = require('mongoose');

var UserModel = mongoose.model('user'),
    ClientModel = mongoose.model('client');

module.exports = function(app, passport){

    var authPath = [
        'qq',
        'github'
    ];

    function next(path, req, res, next){
        req.callbackURL = req.protocol + '://' + req.headers.host + '/auth/' + path + '/' + encodeURIComponent(req.query.next || '/');
        next();
    }

    authPath.forEach(function(x){
        app.get('/auth/' + x, next.bind(null, x), function(req, res, next){
            passport.authenticate(x, {callbackURL: req.callbackURL})(req, res, next);
        });
        app.get('/auth/' + x + '/:next', [next.bind(null, x), function(req, res, next){
            passport.authenticate(x, {callbackURL: req.callbackURL, failureRedirect: '/login?next=' + req.callbackURL})(req, res, next);
        }], function(req, res) {
            res.redirect(req.params.next);
        });
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
        user.buildPassword();
        user.save(function (err, result) {
            if(err) return res.status(500).json(err);
            res.json(result);
        });
    });

    app.get('/login', function(req, res) {
        if(req.isAuthenticated()) return res.redirect(303, '/');
        res.render('login.jade', {
            next: encodeURIComponent(req.query.next ? req.query.next : '/');
        });
    });

    app.post('/login', function(req, res, next) {
        passport.authenticate('local', function(err, user, info) {
            if(err) return res.status(500).json(err);
            if(user) return req.login(user, function(){
                res.redirect(303, req.body.next || '/');
            });
            res.status(401).end();
        })(req, res, next);
    });

    app.get('/me', function(req, res, next) {
        if(req.isAuthenticated()) return res.json(req.user);
        res.status(401).end();
    });

    app.get('/user', function(req, res, next){
        UserModel.find({}, function(err, result){
            res.json(result);
        });
    });

    app.get('/client', function(req, res, next) {

        if(!req.isAuthenticated()) return res.status(401).end();
        var client = new ClientModel({
            user: req.user._id
        });
        client.save(function(err, result){
            if(err) return res.status(500).json(err);
            res.json(result);
        });
    });

};

