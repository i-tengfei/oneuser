module.exports = {
    DATABASE: 'mongodb://localhost:27017/test',
    PORT: 3000,
    SESSION: {
        PERSISTENCE: false,
        DATABASE: 'mongodb://localhost:27017/test',
        SECRET: 'abracadabra',
        COLLECTION: 'sessions'
    },
    AUTH: {
        QQ: {
            CLIENT_ID: 'id',
            CLIENT_SECRET: 'secret'
        },
        GITHUB: {
            CLIENT_ID: 'id',
            CLIENT_SECRET: 'secret'
        }
    }
};
