let filter = function (config, req, res, next) {
    //cors
    if (config.cors) {
        res.header("Access-Control-Allow-Origin", "*");
        res.header("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE");
        res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    }
    
    //write to log
    let userHostAddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    let log = new config.models.log({
        timestamp: new Date(),
        userHostAddress: userHostAddress,
        url: req.originalUrl,
        requestVerb: req.method,
        headers: req.headers,
        requestBody: JSON.stringify(req.body)
    });
    log.save(function (err) {
        if (err)
            return res.status(500).json(err);

        let access_token;
        let authHeader = req.headers.authorization;

        if (req.query['access_token']) {
            access_token = req.query['access_token'];
        }
        else if (authHeader && authHeader.toLowerCase().indexOf('bearer') != -1) {
            let _t = authHeader.split(' ');
            if (_t.length == 2 && _t[0].toLowerCase() == 'bearer')
                access_token = _t[1].toLowerCase().trim();
        }
        else if (req.body['access_token']) {
            access_token = req.body['access_token'];
        }

        if (access_token) {
            config.models.accessToken.findOne({ token: access_token, expires: { $gte: new Date() } }, function (err, db_token) {
                if (err || !db_token)
                    return res.status(401).json({ error: 'invalid_token', error_description: 'token not found', error_uri: '' });

                res.locals.access_token = db_token;
                //user token
                if (db_token.user) {
                    config.models.user.findOne({ _id: db_token.user }, function (err, db_user) {
                        if (err || !db_user)
                            return res.status(401).json({ error: 'invalid_token', error_description: 'user not found', error_uri: '' });

                        res.locals.user = db_user;

                        next();
                    });
                }
                else {
                    next();
                }
            });
        }
        else {
            return res.status(401).json({ error: 'invalid_token', error_description: 'requests require an access token', error_uri: '' });
        }
    });
};

module.exports = filter;
