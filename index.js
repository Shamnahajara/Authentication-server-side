const express = require("express");
const cors = require('cors');
const userRoute = require('./routes/userRoute');
const mongoose = require("mongoose");
require('dotenv').config();

const PORT = process.env.PORT || 3000;

const app = express();
const corsOptions = {
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
};

app.use(cors(corsOptions));
app.use(express.json({ limit: '100mb', extended: true }));
app.use('/', userRoute);

mongoose.connect('mongodb://127.0.0.1:27017/Authentication', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
    .then(() => {
        app.listen(PORT, () => console.log(`Server Port: ${PORT}`));
    })
    .catch((error) => console.log(`${error} did not connect`));
