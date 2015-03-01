var CONFIG = global.CONFIG = require('./config');
if(process.env.NODE_ENV){
    require('onetool').mix(CONFIG, require('./config.' + process.env.NODE_ENV));
}

require('./database');

var auth = require('./auth'),
    express = require('express'),
    session = require('express-session'),
    cookieParser = require('cookie-parser'),
    bodyParser = require('body-parser'),
    MongoStore = require('connect-mongo')(session);

var SESSION = CONFIG.SESSION,
    store = SESSION.PERSISTENCE ?
    new MongoStore({url: SESSION.DATABASE, collection: SESSION.COLLECTION}) :
    new session.MemoryStore({reapInterval: 5 * 60 * 1000});

var passport = auth.passport,
    provider = auth.provider;

var app = express();

app.listen(CONFIG.PORT);
app.engine('jade', require('jade').__express);

app.use('/public', express.static(__dirname + '/public'));
app.use(cookieParser());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));
app.use(session({store: store, secret: SESSION.SECRET, resave: true, saveUninitialized: true}));
app.use(passport.initialize());
app.use(passport.session());
app.use(provider.oauth());
app.use(provider.login());

require('./router')(app, passport);

app.get('*', function(req, res){
    res.status(404).end();
});