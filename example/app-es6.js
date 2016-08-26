const express = require('express');
const app = express();
const conf = require('./config.js');
const model = require('../models')(conf);
const oauthServer = require('../oauth.js');

//api
let oauth = new oauthServer({
    dbinfo: conf,
    tokenExpirationMinutes: 60,
    cors: true,
    clients: [{
        type: 'web',
        client_credentials: {
            scopes: ['app_scope', function(app){
                if(app.data.special)
                    return 'special_scope';
                if(app.user)
                    return 'userapp_scope'
            }]
        },
        password: {
            scopes: ['app_scope', 'user_scope']
        }
    }]
});
app.post('/api/token', oauth.token());
app.use('/api/*', oauth.authorization());

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

app.get('/test', (req, res) => {
    res.send(oauth.cors +"||");
});

app.listen(31337, () => {
    console.log("booted");
});
