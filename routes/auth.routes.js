/* eslint-disable no-shadow */
// routes/auth.routes.js

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User.model');
const { isAuthenticated } = require('../middleware/jwt.middleware');

const router = express.Router();
const saltRounds = 10;

// POST  /auth/signup
router.post('/signup', async (req, res, next) => {
        const { email, password, name } = req.body;

        try {
                if (email === '' || password === '' || name === '') {
                        res.status(400).json({ message: 'Provide email, password and name' });
                        return;
                }

                const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
                if (!emailRegex.test(email)) {
                        res.status(400).json({ message: 'Provide a valid email address.' });
                        return;
                }

                // Use regex to validate the password format
                const passwordRegex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/;
                if (!passwordRegex.test(password)) {
                        res.status(400).json({
                                message: 'Password must have at least 6 characters and contain at least one number, one lowercase and one uppercase letter.',
                        });
                }

                const foundUser = await User.findOne({ email });

                if (foundUser) {
                        res.status(400).json({ message: 'User already exists.' });
                        return;
                }

                const salt = bcrypt.genSaltSync(saltRounds);
                const hashedPassword = bcrypt.hashSync(password, salt);

                const createdUser = await User.create({ email, password: hashedPassword, name });

                const { email: createdEmail, name: createdName, _id: createdId } = createdUser;

                const user = { email: createdEmail, name: createdName, _id: createdId };

                res.status(201).json({ user });
        } catch (error) {
                console.log(error);
                res.status(500).json({ message: 'Internal Server Error' });
                next(error);
        }
});

// POST  /auth/login
router.post('/login', async (req, res, next) => {
        const { email, password } = req.body;

        // Check if email or password are provided as empty string

        try {
                if (email === '' || password === '') {
                        res.status(400).json({ message: 'Provide email and password.' });
                }

                const foundUser = await User.findOne({ email });

                if (!foundUser) {
                        res.status(400).json({ message: 'User not found.' });
                }

                const passwordCorrect = bcrypt.compareSync(password, foundUser.password);

                if (passwordCorrect) {
                        const { _id, email, name } = foundUser;
                        const payload = { _id, email, name };

                        const authToken = jwt.sign(payload, process.env.TOKEN_SECRET, {
                                algorithm: 'HS256',
                                expiresIn: '6h',
                        });

                        res.status(200).json({ authToken });
                } else {
                        res.status(401).json({ message: 'Unable to authenticate the user' });
                }
        } catch (error) {
                res.status(500).json({ message: 'Internal Server Error' });
        }
});

// GET  /auth/verify
router.get('/verify', isAuthenticated, (req, res, next) => {
        console.log(`req.payload`, req.payload);

        res.status(200).json(req.payload);
});

module.exports = router;
