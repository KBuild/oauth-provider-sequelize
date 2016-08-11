const express = require('express');
const app = express();
const model = require('../models')({
    dbname: "palette",
    username: "palette",
    password: "palette123",
    host: "127.0.0.1",
    type: "mysql"
});

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
