var OAuth2Provider = require('oauth2-provider').OAuth2Provider,
    passport = require('passport'),
    mongoose = require('mongoose'),
    request = require('request'),
    LocalStrategy = require('passport-local').Strategy,
    GithubStrategy = require('passport-github').Strategy
    QQStrategy = require('passport-qq').Strategy;

var User = mongoose.model('user');
var Client = mongoose.model('client');

var appScopes = {
    user: '获得您的用户名、邮箱、头像'
};
var AUTH = CONFIG.AUTH;
// ---------- ---------- | Provider | ---------- ---------- //
var grants = {};
var TOKEN_TTL = 3 * 24 * 60 * 60 * 1000;

var provider = new OAuth2Provider({crypt_key: AUTH.CRYPT_KEY, sign_key: AUTH.SIGN_KEY, access_token_uri: '/oauth/token'});

provider.on('enforce_login', function(req, res, authorizeUrl, next) {
    if(req.isAuthenticated()) {
        next(req.user._id);
    } else {
        res.redirect('/login?next=' + encodeURIComponent(authorizeUrl));
    }
});
provider.on('authorize_form', function(req, res, clientAppkey, authorizeUrl) {
    Client.findOne({appkey: clientAppkey}, function(err, result){
        if(err) return res.status(500).end();
        var status = 200,
            scopes = [],
            error = '';
        if(!result){
            status = 400;
            error = '找不到该应用，请检查应用AppKey！';
        }
        if(req.query.scope){
            scopes = req.query.scope.split(',');
            if(!scopes.some(function(x){return x==='user'})){
                scopes.unshift('user');
            }
        }
        scopes = scopes.map(function(x){
            return {
                name: x,
                info: appScopes[x]
            };
        }).filter(function(x){return !!appScopes[x.name]});

        // var clients = req.user.clients;
        // if(clients && clients.length){
        //     for(var i = 0; i < clients.length; i++){
        //         var client = clients[i];
        //         if(client.appkey === clientAppkey){
        //             var data = provider.serializer.parse(client.token);
        //             var userID = data[0],
        //                 clientID = data[1],
        //                 grantDate = new Date(data[2]),
        //                 extraData = data[3];
        //             if(userID === ''+req.user._id && clientID === clientAppkey && grantDate.getTime() + TOKEN_TTL > Date.now()){
        //                 // TODO: 自动跳转
        //             }
        //         }
        //     }
        // }

        res.status(status).render('authorize.jade', {
            authorizeUrl: authorizeUrl,
            client: result,
            scopes: scopes,
            error: error
        });
    });
});
provider.on('save_grant', function(req, clientAppkey, code, next) {
    var userID = req.user._id;
    if(!(userID in grants))
        grants[userID] = {};

    var scope = req.body.scope;
    if(!scope){
        scope = 'user';
    }
    if(!Array.isArray(scope)){
        scope = [scope]
    }
    if(scope.indexOf('user') === -1){
        scope.unshift('user');
    }

    grants[userID][clientAppkey] = {
        scopes: scope.filter(function(x){
            return !!appScopes[x];
        }),
        code: code
    };
    next();
});
provider.on('remove_grant', function(userID, clientAppkey, code) {
    if(grants[userID] && grants[userID][clientAppkey])
        delete grants[userID][clientAppkey];
});
provider.on('lookup_grant', function(clientAppkey, clientSecret, code, next) {
    Client.findOne({
        appkey: clientAppkey,
        secret: clientSecret
    }, function (err, user) {
        if(!err && user){
            for(var userID in grants) {
                var clients = grants[userID];
                if(clients[clientAppkey] && clients[clientAppkey].code == code){
                    return next(null, userID);
                }
            }
        }else{
            next(new Error('应用未授权！'));
        }
    });
});
provider.on('create_access_token', function(userID, clientAppkey, next) {
    var extra_data = {};
    if(grants[userID] && grants[userID][clientAppkey]){
        extra_data.scopes = grants[userID][clientAppkey].scopes
    }else{
        // self
        extra_data.scopes = ['user'];
    }
    next(extra_data);
});
provider.on('save_access_token', function(userID, clientAppkey, accessToken) {
    var token = accessToken.access_token;
    User.findOneAndUpdate({
        '_id': userID,
        'clients.appkey': {$ne: clientAppkey}
    }, {
        $push: {clients: {'appkey': clientAppkey, token: token}}
    }, function(err, user){
        if(!err && !user){
            User.findOneAndUpdate({
                '_id': userID,
                'clients.appkey': clientAppkey
            }, {
                $set: {'clients.$.token': token}
            }, function(err, user){});
        }
    });
    accessToken.scope = grants[userID][clientAppkey].scopes;
});
provider.on('access_token', function(req, token, next) {
    if(token.grant_date.getTime() + TOKEN_TTL < Date.now()) {
        return next(new Error('授权已过期'));
    } else {
        User.findById(token.user_id, function(err, user){
            if(err) return res.status(500).end();
            if(!user) return res.status(403).end('用户未找到！');
            if(!user.clients || !user.clients.length) return res.status(403).end('用户未授权该应用！');
            if(!user.clients.some(function(x){
                return x.appkey === token.client_id;
            })) return res.status(403).end('用户未授权该应用！');
            
            req.login(user, function(){
                next();
            });
        });
    }
});
provider.on('client_auth', function(clientAppkey, client_secret, username, password, next) {
    // TODO:
    // if(client_id == '1' && username == 'guest') {
        var conditions = {};
        conditions.username = username;
        User.findOne(conditions, function (err, user) {
            if (err) {return next(err)}
            if (!user) {
                return next(new Error('Unknown user'));
            }
            if (!user.authenticate(password)) {
                return next(new Error('Invalid password'));
            }
            next(null, user._id);
        } );
    // }

    // return next(new Error('client authentication denied'));
});
// ---------- ---------- | Passport | ---------- ---------- //
passport.serializeUser(function(user, done) {
    done(null, user);
});

passport.deserializeUser(function(user, done) {
    User.findById(user._id, done);
});
// Local
passport.use(new LocalStrategy({
        usernameField: 'username',
        passwordField: 'password'
    }, function(username, password, done) {
        var conditions = {};
        conditions.username = username;
        User.findOne(conditions, function (err, user) {
            if (err) {return done(err)}
            if (!user) {
                return done(null, false, {message:'Unknown user'});
            }
            if (!user.authenticate(password)) {
                return done(null, false, {message: 'Invalid password'})
            }
            return done(null, user);
        } );
    })
);
// 第三方
function auth(accessToken, refreshToken, profile, done) {
    profile.accessToken = accessToken;
    profile.refreshToken = refreshToken;
    if(!accessToken || !profile.id) return done(new Error());
    User.authUser(profile.id, profile, function(err, result, isNew){
        done(err, result);
    });
}
// Github
passport.use(new GithubStrategy({
    clientID: AUTH.GITHUB.CLIENT_ID,
    clientSecret: AUTH.GITHUB.CLIENT_SECRET
}, auth));
// QQ
passport.use(new QQStrategy({
    clientID: AUTH.QQ.CLIENT_ID,
    clientSecret: AUTH.QQ.CLIENT_SECRET
}, auth));

exports.provider = provider;
exports.passport = passport;
