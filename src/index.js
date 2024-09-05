import express from 'express';
import cors from 'cors';
import db from './db/database.mjs';

const app = express();
const PORT = 3001;

app.use(cors());
app.use(express.json());

app.get('/api/users',async (req, res) => {
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
        const newUser = await db.create({
            name,
            email,
            username,
            password
        });
        return res.status(201).send({ message: 'User created successfully', status: 201 });
    } catch (error) {
        console.error('Error creating user:', error);
        return res.status(500).send({ message: 'Internal Server Error' });
    }
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
