const userModel = require('../model/userModel');
require('dotenv').config();
const sha256 = require("js-sha256");
const SALT = process.env.SALT;
const { generateToken } = require('../middleware/auth')

//Register//
const register = async (req, res) => {
    try {
        let { name, email, password } = req.body;
        email = email.trim();
        password = password.trim();
        const existingUser = await userModel.findOne({ email });
        if (existingUser) {
            return res.status(200).json({ errmsg: "User already exists" });
        } else {
            const newUser = await userModel.create({
                name,
                email,
                password: sha256(password + SALT),
            });
            res.status(200).json({ message: "User registered successfully" });
        }
    } catch (error) {
        console.error('Error during registration:', error);
        res.status(500).json({ errmsg: "Server error" });
    }
};

//Login//
const login = async (req, res) => {
    try {
        let { email, password } = req.body;
        const user = await userModel.findOne({
            $and: [{ email }, { password: sha256(password + SALT) }],
        });
        if (!user) {
            res.status(400).json({ errmsg: "Password or email is incorrect" });
        } else {
            const token = generateToken(user._id, "user");
            res.status(200).json({
                message: "user successfully login",
                name: user.name,
                token,
                userId: user._id,
            });
        }
    } catch (error) {
        res.status(500).json({ errmsg: "server error" });
        console.log(error)
    }
};

module.exports = {
    register,
    login
};
