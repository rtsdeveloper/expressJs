import express from 'express';
import cors from 'cors';
import db from './db/database.mjs';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const app = express();
const PORT = 3001;
const JWT_SECRET = 'rtsdeveloper';

app.use(cors());
app.use(express.json());

const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) {
        return res.status(401).send({ message: 'No token provided' });
    }
    jwt.verify(token.split(" ")[1], JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).send({ message: 'Failed to authenticate token' });
        }
        req.userId = decoded.id;
        next();
    });
};

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
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '1h' });
    res.status(200).send({
        status: 200,
        message: 'Successfully logged in',
        data: {
            username: user.username,
            name: user.name,
            email: user.email,
            token
        },
    });
});

app.get('/api/profile', verifyToken, async (req, res) => {
    try {
        const user = await db.findById(req.userId);
        if (!user) {
            return res.status(404).send({ message: 'User not found' });
        }
        return res.status(200).send({
            status: 200,
            message: 'Successfully fetched current user data',
            data: {
                name: user.name,
                email: user.email,
                username: user.username
            },
        });
    } catch (error) {
        return res.status(500).send({ message: 'Internal server error' });
    }
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});