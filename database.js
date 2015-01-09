var mongoose = require('mongoose'),
    crypto = require('crypto');
var Schema = mongoose.Schema;

mongoose.connect(CONFIG.DATABASE);

var Client = new Schema({
    user: {type: Schema.ObjectId, ref: 'user', index: true},
    appkey: {type: String, index: {unique: true}},
    secret: {type: String, index: {unique: true}},

    createTime: {type: Date, default: Date.now()},
    updateTime: {type: Date, default: Date.now()}
});
Client.pre('save', function(next){
    this.appkey = this.encrypt(this.user + this._id, makeSalt());
    this.secret = this.encrypt(this.user + this._id + 'oneuser', makeSalt());
    next();
});

Client.methods = {
    encrypt: function (string, salt) {
       return crypto.createHmac('sha1', salt).update(string).digest('hex');
    }
};

var User = new Schema({
    username: {type: String, index: {unique: true}},
    password: {type: String},
    email: {type: String, index: {unique: true}},

    salt: {type: String, default: ''},

    auth: {},

    clients: [],

    createTime: {type: Date, default: Date.now()},
    updateTime: {type: Date, default: Date.now()}
});

User.set('toJSON', {
    transform: function(doc, ret, options) {
        delete ret.password;
        delete ret.salt;
        delete ret.__v;
        delete ret.auth;
        delete ret.clients;
        return ret;
    }
});

User.pre('save', function(next) {
    this.salt = makeSalt();
    this.password = this.encryptPassword(this.password);
    next();
});

User.methods = {
    encryptPassword: function (password) {
        return crypto.createHmac('sha1', this.salt).update(password).digest('hex');
    },

    authenticate: function (password) {
        return this.encryptPassword(password) === this.password;
    }
};

function makeSalt(){
    return Math.round((new Date().valueOf() * Math.random())) + '';
}

mongoose.model('client', Client, 'client');
mongoose.model('user', User, 'user');
