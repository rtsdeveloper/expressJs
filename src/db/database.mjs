import mongoose from 'mongoose';

const mongoDB = 'mongodb://localhost:27017/user';

mongoose.connect(mongoDB);

const database = mongoose.connection;

database.on('error', console.error.bind(console, 'connection error:'));
database.once('open', () => {
    console.log('Connected to MongoDB');
});

const db = mongoose.model('User', {
    username: String,
    name: String,
    email: String,
    password: String
});

export default db;
