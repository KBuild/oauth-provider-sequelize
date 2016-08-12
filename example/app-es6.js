const express = require('express');
const app = express();
const conf = require('./config.js');
const model = require('../models')(conf);

app.get('/', (req, res) => {
    res.send("test");
});

app.get('/db/:tbl', (req, res) => {
    if(req.params.tbl === "all") {
        res.send(Object.keys(model));
    }
    else {
        res.send(model[req.params.tbl].toString());
    }
});

app.listen(31337, () => {
    console.log("booted");
});
