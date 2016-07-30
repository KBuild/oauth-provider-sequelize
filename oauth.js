let filter = require('./filter.js');
let token = require('./token.js');
let extend = require('extend');
let models = require('./models.js');
let crypto = require('crypto');

/**
    * @api {post} /api/token Obtaining an access token
    * @apiDescription Required for all requests
    * @apiVersion 0.1.0
    * @apiName PostToken
    * @apiGroup Authorization
    * 
    * @apiHeader {string} Authorization Basic base64(KEY+':'+SECRET)
    * 
    * @apiParam (Application) {string} grant_type=client_credentials
    * 
    * @apiParam (User) {string} grant_type=password
    * @apiParam (User) {string} username
    * @apiParam (User) {string} password
    *  
    * @apiHeaderExample {string} example header:
    * Authorization: Basic RDA4MEYwMzgtNUM5MS00RkI3LUI5OUMtNDJERENFMTQ1RjQxOkI5NUIxOTVELTIyNkItNEM2RS1BNDNDLUE0MkYwRDREQzNEMg==
    * 
    * @apiSampleRequest /api/token
    */

let oauth = (function () {
    function oauth(options) {
        //in order to call it without 'new'
        if (!(this instanceof oauth))
            return new oauth(options);

        if (!options.dbinfo)
            throw new Error('dbinfo not specified in config');

        let defaults = {
            tokenExpirationMinutes: 60,
            cors: true,
            clients: []
        };
        options = extend(true, {}, defaults, options);

        this.config = options;
        this.config.models = models(options.dbinfo);
    }

    oauth.prototype.createUser = function (user, pass, roles, data, callback) {
        if (!roles || roles.length == 0)
            roles = ['admin'];

        if (!user || !pass)
            return callback('No user or password specified !');

        let salt = crypto.randomBytes(10).toString('hex');
        let pass_salt = pass + salt;
        let shasum = crypto.createHash('sha1');
        shasum.update(pass_salt)
        let hash = shasum.digest('hex');

        let dbuser = this.config.models.user({
            username: user,
            hash: hash,
            salt: salt,
            isBlocked: false,
            attemptCount: 0,
            roles: roles,
            timestamp: new Date(),
            createdAt: new Date(),
            isDeleted: false,
            data: data
        });

        dbuser.save(function (err, data) {
            return callback(err, data);
        });
    };

    oauth.prototype.registerClient = function (name, key, secret, type, platform, data, dev_token, callback) {
        if (!name || !key || !secret || !type || !platform)
            callback('All parameters are required');
        let self = this;
        let app = new this.config.models.application({
            name: name,
            key: key,
            secret: secret,
            type: type,
            platform: platform,
            data: data
        });

        app.save(function (err, data) {
            if (err)
                return callback('Error updating applications');

            if (dev_token) {
                let tokens = [];
                tokens.push({
                    "token": "dev",
                    "expires": new Date("2020-12-23T11:03:14.335Z"),
                    "isValid": true,
                    "grantType": "client_credentials",
                    "issuedAt": new Date("2015-01-01T10:03:14.336Z"),
                    "scopes": dev_token.scopes,
                    "applicationID": data._id
                });

                self.config.models.accessToken.collection.insert(tokens, function (err, data) {
                    return callback(err, data);
                });
            } else {
                return callback(err, data);
            }
        });
    };
    
    //express
    oauth.prototype.authorization = function (req, res, next) {
        let self = this;
        return function (req, res, next) {
            filter(self.config, req, res, next);
        }
    };

    oauth.prototype.token = function () {
        let self = this;

        return function (req, res, next) {
            token(self.config, req, res, next);
        }
    };
    
    //statics
    //no config available
    oauth.authorize = function (scopes) {
        if (scopes && typeof (scopes) == 'string')
            scopes = [scopes];

        return function (req, res, next) {
            let context_scopes = res.locals.access_token.scopes;
            if (scopes && scopes.length > 0) {
                //check if at least one context_scope is in requested scopes
                let scope_intersect = context_scopes.filter(function (x) {
                    return scopes.indexOf(x) != -1;
                });
                if (scope_intersect.length == 0)
                    return res.status(401).json({ error: 'invalid_token', error_description: 'not authorized for this request', error_uri: '' });
            }
            next();
        }
    };

    return oauth;
})();

module.exports = oauth;
