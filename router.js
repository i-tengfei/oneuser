var mongoose = require('mongoose');

var UserModel = mongoose.model('user'),
    ClientModel = mongoose.model('client');

module.exports = function(app, passport){

    app.post('/auth', function(req, res, next){
        if(req.isAuthenticated()){
            res.send(req.user);
        }else{
            res.sendStatus(403);
        }
    });

    app.all('/logout', function(req, res){
        req.logout();
        res.redirect('/');
    });

    app.get('/signup', function(req, res, next) {
        res.render('signup.jade');
    });

    app.post('/signup', function(req, res, next) {
        var user = new UserModel(req.body);
        user.save(function (err, result) {
            if(err){
                res.send(err);
            }else{
                res.send(result);
            }
        });
    });

    app.get('/login', function(req, res, next) {
        if(req.isAuthenticated()){
            res.writeHead(303, {Location: '/'});
            return res.end();
        }

        res.render('login.jade', {
            next_url: req.query.next ? req.query.next : '/'
        });
    });

    app.post('/login', function(req, res, next) {
        passport.authenticate('local', function(err, user, info) {
            if(user){
                req.login(user, function(){
                    res.writeHead(303, {Location: req.body.next || '/'});
                    res.end();
                });
            }else{
                res.send('登录错误！');
            }
        })(req, res, next);
    });

    app.get('/user', function(req, res, next) {
        if(req.isAuthenticated()){
            res.send(req.user);
        } else {
            res.status(403).send('用户未登录！');
        }
    });

    app.get('/client', function(req, res, next) {
        if(req.isAuthenticated()){
            var client = new ClientModel({
                user: req.user._id
            });
            client.save(function(err, result){
                if(err){
                    res.send(err);
                }else{
                    res.send(result);
                }
            });
        } else {
            res.status(403).send('用户未登录！');
        }
    });

};

