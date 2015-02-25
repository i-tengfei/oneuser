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

var Auth = new Schema({
    provider: {type: String},
    id: {type: String, index: {unique: true}},
    emails: [String],
    profile: {type: String},
    accessToken: {type: String},
    refreshToken: {type: String},
    _raw: {type: String},
    _json: {}
});

Auth.set('toJSON', {
    transform: function(doc, ret, options) {
        delete ret.accessToken;
        delete ret.refreshToken;
        return ret;
    }
});

var User = new Schema({
    username: {type: String, index: {unique: true}},
    password: {type: String},
    email: {type: String, index: {unique: true}},

    salt: {type: String, default: ''},

    auth: [Auth],

    clients: [],

    createTime: {type: Date, default: Date.now()},
    updateTime: {type: Date, default: Date.now()}
});

User.set('toJSON', {
    transform: function(doc, ret, options) {
        delete ret.password;
        delete ret.salt;
        delete ret.__v;
        delete ret.clients;
        return ret;
    }
});

User.pre('save', function(next) {
    this.updateTime = Date.now();
    next();
});

User.methods = {
    encryptPassword: function (password) {
        return crypto.createHmac('sha1', this.salt).update(password).digest('hex');
    },

    authenticate: function (password) {
        return this.encryptPassword(password) === this.password;
    },

    buildPassword: function(password){
        this.salt = makeSalt();
        this.password = this.encryptPassword(password || this.password);
    }
};
User.statics = {
    authUser: function (id, doc, callback){
        var self = this;
        this.findOne({'auth.id': id}, function(err, result) {
            if(err){return console.log(err);}
            if(result) {
                var user = result.auth[result.auth.map(function(x){
                    return ''+x.id;
                }).indexOf(''+id)];
                for(var key in doc){
                    user[key] = doc[key];
                }
                result.save(function(err){
                    if(err){return console.log(err);}
                    callback(err, result, false);
                });
            } else {
                var obj = new self({username: id});
                switch(doc.provider){
                    case 'github':
                        obj.email = doc.emails[0].value;
                        doc.profile = doc.profileUrl;
                        break;
                    default: 
                        obj.email = id + '@malubei.com';
                        break;
                }
                obj.auth.push(doc);
                obj.save(function(err) {
                    callback(err, obj, true);
                });
            }
        });
    }
};
// User.static('findByName', function (name, callback) {
//   return this.find({ name: name }, callback);
// });

function makeSalt(){
    return Math.round((new Date().valueOf() * Math.random())) + '';
}

mongoose.model('client', Client, 'client');
mongoose.model('user', User, 'user');
