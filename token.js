let crypto = require('crypto');
let moment = require('moment');

let maliciousAttempt = function (ipAttempt, res) {
    ipAttempt.timestamp = new Date();
    if (ipAttempt.attemptCount >= 10) {
        ipAttempt.isBlocked = true;
    } else {
        ipAttempt.attemptCount++;
    }
    ipAttempt.save(function (err) {
        if (err)
            return res.status(500).json(err);

        return res.status(401).json({ error: 'invalid_client', error_description: '', error_uri: '' });
    });
};
let validateUser = function (dbUser, password) {
    let pass_salt = password + dbUser.salt;
    let shasum = crypto.createHash('sha1');
    shasum.update(pass_salt)
    let hashedPassword = shasum.digest('hex');

    return dbUser.hash == hashedPassword
};

module.exports = function (config, req, res, next) {
    let userHostAddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress;

    if (!req.body)
        return res.status(400).json({ error: 'No message body found' });

    let log = new config.models.log({
        timestamp: new Date(),
        userHostAddress: userHostAddress,
        url: req.url,
        requestVerb: req.method,
        headers: req.headers,
        requestBody: req.body
    });
    
    //save log entry
    log.save(function (err) {
        if (err)
            return res.status(500).json(err);

        config.models.ipAttempt.findOne({ userHostAddress: userHostAddress }, function (err, ipAttempt) {
            if (err)
                return res.status(500).json(err);
            
            //first time for this IP
            if (!ipAttempt) {
                let ipAttempt = new config.models.ipAttempt({
                    userHostAddress: userHostAddress,
                    timestamp: new Date(),
                    attemptCount: 0,
                    isBlocked: false
                });
                ipAttempt.save(function (err) {
                    if (err)
                        return res.status(500).json(err);
                });
            } else {
                //check if ip is blocked
                if (ipAttempt.isBlocked)
                    return res.status(401).json({ error: 'invalid_client', error_description: 'ip is blocked', error_uri: '' });
            }
            
            //check auth headers
            let authHeader = req.headers.authorization;
            if (authHeader && authHeader.toLowerCase().indexOf('basic') != -1) {
                let _t = authHeader.split(' ');
                if (_t.length == 2 && _t[0].toLowerCase() == 'basic')
                    clientBase64 = _t[1].trim();
                let buffer = new Buffer(clientBase64, 'base64').toString();
                let clientString = buffer.split(':');
                if (clientString.length == 2) {
                    let clientID = clientString[0];
                    let clientSecret = clientString[1];

                    config.models.application.findOne({ key: clientID, secret: clientSecret }, function (err, application) {
                        if (err)
                            return req.status(500).json(err);
                        if (application) {
                            //search in config for app type
                            let clientConfig = config.clients.filter(function (x) { return x.type == application.type; })[0];
                            if (clientConfig) {
                                if (req.body.grant_type == 'client_credentials' && clientConfig.client_credentials) {
                                    //generate token
                                
                                    let scopes = [];
                                    //app type allows for client_credentials grant
                                    if (clientConfig.client_credentials.scopes) {
                                        clientConfig.client_credentials.scopes.forEach(function (x) {
                                            if (typeof (x) == 'string') {
                                                scopes.push(x);
                                            } else if (typeof (x) == 'function') {
                                                let _s = x(application);
                                                if (_s)
                                                    scopes.push(_s);
                                            }
                                        });
                                    }
                                        
                                    //issue the token
                                    let token_str = crypto.randomBytes(64).toString('hex');
                                    let token_expires = moment().add(config.tokenExpirationMinutes, 'minutes').toDate();
                                    let token = new config.models.accessToken({
                                        token: token_str,
                                        expires: token_expires,
                                        isValid: true,
                                        grantType: req.body.grant_type,
                                        issuedAt: new Date(),
                                        scopes: scopes,
                                        applicationID: application
                                    });
                                    if (application.user)
                                        token.user = application.user;

                                    token.save(function (err) {
                                        if (err)
                                            return req.status(500).json(err);

                                        return res.json({
                                            access_token: token_str,
                                            token_type: 'bearer',
                                            expires_in: moment(token_expires).diff(moment(), 'seconds'),
                                            scope: token.scopes.join(' ')
                                        });
                                    });
                                } else if (req.body.grant_type == 'password' && clientConfig.password) {
                                    if (req.body.username && req.body.password) {
                                        //find username in database
                                        config.models.user.findOne({ username: req.body.username }, function (err, dbUser) {
                                            if (err)
                                                return req.status(500).json(err);

                                            if (dbUser && !dbUser.isBlocked) {
                                                if (validateUser(dbUser, req.body.password)) {
                                                    //reset attempt count
                                                    dbUser.attemptCount = 0;
                                                    dbUser.save(function (err) {
                                                        if (err)
                                                            return res.status(500).json(err);

                                                        let scopes = [];
                                                        //app type allows for password grant
                                                        if (clientConfig.password.scopes) {
                                                            clientConfig.password.scopes.forEach(function (x) {
                                                                if (typeof (x) == 'string') {
                                                                    scopes.push(x);
                                                                } else if (typeof (x) == 'function') {
                                                                    let _s = x(dbUser);
                                                                    if (_s)
                                                                        scopes.push(_s);
                                                                }
                                                            });
                                                        }

                                                        //generate token
                                                        let token_str = crypto.randomBytes(64).toString('hex');
                                                        let token_expires = moment().add(config.tokenExpirationMinutes, 'minutes').toDate();
                                                        let token = new config.models.accessToken({
                                                            token: token_str,
                                                            expires: token_expires,
                                                            isValid: true,
                                                            grantType: req.body.grant_type,
                                                            issuedAt: new Date(),
                                                            scopes: scopes,
                                                            applicationID: application,
                                                            user: dbUser._id
                                                        });

                                                        token.save(function (err) {
                                                            if (err)
                                                                return req.status(500).json(err);

                                                            return res.json({
                                                                access_token: token_str,
                                                                token_type: 'bearer',
                                                                expires_in: moment(token_expires).diff(moment(), 'seconds'),
                                                                scope: token.scopes.join(' ')
                                                            });
                                                        });
                                                    });
                                                } else {
                                                    //bad attempt
                                                    dbUser.attemptCount++;
                                                    if (dbUser.attemptCount >= 5)
                                                        dbUser.isBlocked = true;
                                                    dbUser.save(function (err) {
                                                        if (err)
                                                            return res.status(500).json(err);

                                                        return res.status(401).json({ error: 'invalid_grant', error_description: 'user or password is incorrect', error_uri: '' });
                                                    });
                                                }
                                            } else {
                                                //user doesn't exist or is blocked
                                                return res.status(401).json({ error: 'invalid_grant', error_description: 'user not found or is blocked', error_uri: '' });
                                            }
                                        });
                                    } else {
                                        return res.status(400).json({ error: 'invalid_request', error_description: 'user or password not specified', error_uri: '' });
                                    }
                                } else {
                                    return res.status(400).json({ error: 'unsupported_grant_type', error_description: '', error_uri: '' });
                                }
                            } else {
                                return res.status(400).json({ error: 'unsupported_grant_type', error_description: '', error_uri: '' });
                            }
                        }
                        else {
                            return maliciousAttempt(ipAttempt, res);
                        }
                    });
                } else {
                    return res.status(400).json({ error: 'invalid_request', error_description: 'auth basic', error_uri: '' });
                }
            } else {
                return res.status(400).json({ error: 'invalid_request', error_description: 'auth basic', error_uri: '' });
            }
        });
    });
};
