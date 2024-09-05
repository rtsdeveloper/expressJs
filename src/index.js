import express from 'express';
import cors from 'cors';
import db from './db/database.mjs';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const app = express();
const PORT = 3001;

app.use(cors());
app.use(cookieParser());
app.use(express.json());

app.get('/api/users', async (req, res) => {
    const userList = await db.find();
    res.status(200).send({
        status: 200,
        message: 'Successfully fetched data',
        data: userList,
    });
});

app.post("/api/register", async (req, res) => {
    const { name, email, username, password } = req.body;

    if (!name || !email || !username || !password) {
        return res.status(400).send({ message: 'Bad request' });
    }

    try {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        await db.create({
            name,
            email,
            username,
            password: hashedPassword
        });

        return res.status(201).send({ message: 'User created successfully', status: 201 });
    } catch (error) {
        console.error('Error creating user:', error);
        return res.status(500).send({ message: 'Internal Server Error' });
    }
});


app.delete("/api/delete/:id", async (req, res) => {
    const { id } = req.params;
    try {
        const user = await db.findByIdAndDelete(id);
        if (!user) {
            return res.status(404).send({ message: 'User not found', status: 404 });
        }
        return res.status(200).send({ message: 'User deleted successfully', status: 200 });
    } catch (error) {
        console.error('Error deleting user:', error);
        return res.status(500).send({ message: 'Internal Server Error' });
    }
})

app.get("/api/user/:id", async (req, res) => {
    const { id } = req.params;
    const user = await db.findById(id);
    if (!user) {
        return res.status(404).send({ message: 'User not found', status: 404 });
    }
    res.status(200).send({
        status: 200,
        message: 'Successfully fetched data',
        data: user,
    });
})

app.post("/api/login", async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).send({ message: 'Bad request' });
    }

    const user = await db.findOne({ email });
    if (!user) {
        return res.status(404).send({ message: 'User not found', status: 404 });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
        return res.status(401).send({ message: 'Invalid credentials', status: 401 });
    }

    const token = jwt.sign({ id: user._id }, 'rtsdeveloper');

    res.cookie('token', token);

    res.status(200).send({
        status: 200,
        message: 'Successfully logged in',
        data: {
            username: user.username,
            name: user.name,
            email: user.email,
            username: user.username,
            token
        },
    });
});

app.post("/api/cookie", (req, res) => {
    const token = req.cookies.token;
    if (!token) {
        return res.status(401).send({ message: 'Unauthorized' });
    }
    jwt.verify(token, 'rtsdeveloper', (err, decoded) => {
        console.log(err)
        if (err) {
            return res.status(401).send({ message: 'Unauthorized' });
        }
        return res.status(200).send({ message: 'Authorized' });
    });
})

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});