module.exports = {
    DATABASE: 'mongodb://localhost:27017/test',
    PORT: 3000,
    SESSION: {
        PERSISTENCE: false,
        DATABASE: 'mongodb://localhost:27017/test',
        SECRET: 'abracadabra',
        COLLECTION: 'sessions'
    }
};
