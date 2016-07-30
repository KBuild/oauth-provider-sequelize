const Sequelize = require('sequelize');
let models = function (dbconf) {
    let sequelize = new Sequelize(dbconf.dbname, dbconf.username, dbconf.password, {
        host: dbconf.host,
        dialect: dbconf.type
    });
    let prefix = dbconf.tbl_prefix == undefined ? "oauth_" : dbconf.tbl_prefix;
    sequelize
      .authenticate()
      .then(function(err) {
        console.log('Connection has been established successfully.');
      })
      .catch(function (err) {
        console.log('Unable to connect to the database:', err);
        return null;
      });

    let application = sequelize.define(prefix + 'application', {
        name: Sequelize.STRING,
        key: { type: Sequelize.STRING, primaryKey: true },
        secret: Sequelize.STRING,
        type: Sequelize.STRING,
        platform: Sequelize.STRING,
        uri: Sequelize.STRING,
        user: { type: mongoose.Schema.ObjectId, ref: 'userSchema' },
        data: Sequelize.TEXT
    });

    let logs = sequelize.define(prefix + 'logs', {
        timestamp: Sequelize.DATE,
        userHostAddress: Sequelize.STRING,
        url: Sequelize.STRING,
        requestVerb: Sequelize.STRING,
        headers: Sequelize.TEXT,
        requestBody: Sequelize.TEXT
    });

    let ipAttempts = sequelize.define(prefix + 'ipAttempts', {
        userHostAddress: Sequelize.STRING,
        timestamp: Sequelize.DATE,
        attemptCount: Sequelize.INTEGER,
        isBlocked: Sequelize.BOOLEAN
    });

    let accessToken = sequelize.define(prefix + 'accessToken', {
        token: { type: Sequelize.STRING, primaryKey: true },
        expires: Sequelize.DATE,
        isValid: Sequelize.BOOLEAN,
        grantType: Sequelize.STRING,
        issuedAt: Sequelize.DATE,
        scopes: Sequelize.ARRAY(Sequelize.STRING),
        user: { type: mongoose.Schema.ObjectId, ref: 'userSchema' },
        applicationID: { type: mongoose.Schema.ObjectId, ref: 'applicationSchema' }
    });

    let user = sequelize.define(prefix + 'user', {
        username: { type: Sequelize.STRING, primaryKey: true },
        hash: Sequelize.STRING,
        salt: Sequelize.STRING,
        isBlocked: Sequelize.BOOLEAN,
        attemptCount: Sequelize.INTEGER,
        roles: Sequelize.ARRAY(Sequelize.STRING),
        timestamp: Sequelize.DATE,
        createdAt: Sequelize.DATE,
        isDeleted: Sequelize.BOOLEAN,
        data: Sequelize.TEXT
    });

    /*TODO: fill model data from database(ex. mariadb)*/
    return {
        application: model.app,
        ipAttempt: model.ipAttempt,
        log: model.log,
        accessToken: model.accessToken,
        user: model.user
    }
};

module.exports = models;
