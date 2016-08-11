const Sequelize = require('sequelize');
const forceSync = true;
let models = function (dbconf) {
    let sequelize = new Sequelize(dbconf.dbname, dbconf.username, dbconf.password, {
        host: dbconf.host,
        dialect: dbconf.type
    });
    let prefix = dbconf.tbl_prefix == undefined ? "oauth_" : dbconf.tbl_prefix;
    sequelize
      .authenticate()
      .then((err) => {
        console.log('Connection has been established successfully.');
      })
      .catch((err) => {
        console.log('Unable to connect to the database:', err);
        return null;
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

    user.sync({force: forceSync}).then(() => {
        console.log("user synced");
    });

    let application = sequelize.define(prefix + 'application', {
        name: Sequelize.STRING,
        key: { type: Sequelize.STRING, primaryKey: true },
        secret: Sequelize.STRING,
        type: Sequelize.STRING,
        platform: Sequelize.STRING,
        uri: Sequelize.STRING,
        user: {
            type: Sequelize.INTEGER,
            references: {
                model: user,
                key: 'id',
            }
        },
        data: Sequelize.TEXT
    });

    application.sync({force: forceSync}).then(() => {
        console.log("application synced");
    });

    let logs = sequelize.define(prefix + 'logs', {
        timestamp: Sequelize.DATE,
        userHostAddress: Sequelize.STRING,
        url: Sequelize.STRING,
        requestVerb: Sequelize.STRING,
        headers: Sequelize.TEXT,
        requestBody: Sequelize.TEXT
    });

    logs.sync({force: forceSync}).then(() => {
        console.log("logs synced");
    });

    let ipAttempts = sequelize.define(prefix + 'ipAttempts', {
        userHostAddress: Sequelize.STRING,
        timestamp: Sequelize.DATE,
        attemptCount: Sequelize.INTEGER,
        isBlocked: Sequelize.BOOLEAN
    });

    ipAttempts.sync({force: forceSync}).then(() => {
        console.log("ipAttempts synced");
    });

    let accessToken = sequelize.define(prefix + 'accessToken', {
        token: { type: Sequelize.STRING, primaryKey: true },
        expires: Sequelize.DATE,
        isValid: Sequelize.BOOLEAN,
        grantType: Sequelize.STRING,
        issuedAt: Sequelize.DATE,
        scopes: Sequelize.STRING,
        user: { 
            type: Sequelize.INTEGER,
            references: {
                model: user,
                key: 'id',
            }
        },
        applicationID: { 
            type: Sequelize.INTEGER,
            references: {
                model: application,
                key: 'id',
            }
        }
    });

    accessToken.sync({force: forceSync}).then(() => {
        console.log("accessToken synced");
    });

    /*TODO: fill model data from database(ex. mariadb)*/
    return {
        application: application,
        ipAttempt: ipAttempts,
        log: logs,
        accessToken: accessToken,
        user: user
    }
};

module.exports = models;
