var CONFIG = global.CONFIG = require('./config');
if(process.env.NODE_ENV){
    require('onetool').mix(CONFIG, require('./config.' + process.env.NODE_ENV));
}

require('./database');

var express = require('express'),
    auth = require('./auth'),
    mongoose = require('mongoose'),
    session = require('express-session'),
    cookieParser = require('cookie-parser'),
    bodyParser = require('body-parser'),
    MongoStore = require('connect-mongo')(session);

var SESSION = CONFIG.SESSION;
var store = new session.MemoryStore({reapInterval: 5 * 60 * 1000});
var UserModel = mongoose.model('user');

var passport = auth.passport,
    provider = auth.provider,
    app = express();

app.use(cookieParser());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));
if(SESSION.PERSISTENCE){
    store = new MongoStore({
        url: SESSION.DATABASE,
        collection: SESSION.COLLECTION
    });
}
app.use(session({store: store, secret: SESSION.SECRET, resave: true, saveUninitialized: true}));
app.use(passport.initialize());
app.use(passport.session());
app.use(provider.oauth());
app.use(provider.login());
app.listen(config.PORT);

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
    res.end('<html><form method="post" action="/signup"><input type="text" placeholder="username" name="username"><input type="password" placeholder="password" name="password"><button type="submit">Login</button></form>');
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

    var next_url = req.query.next ? req.query.next : '/';

    res.end('<html><form method="post" action="/login"><input type="hidden" name="next" value="' + next_url + '"><input type="text" placeholder="username" name="username"><input type="password" placeholder="password" name="password"><button type="submit">Login</button></form>');
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
app.get('/auth/oneuser', passport.authenticate('oneuser'));
app.get('/auth/oneuser/callback', passport.authenticate('oneuser', { failureRedirect: '/login' }), function(req, res) {
    res.redirect('/');
});
