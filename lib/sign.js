'use strict';

const JWT = require('jsonwebtoken');
const Hoek = require('hoek');
const InitConfig = require('./default');

module.exports = (data, config) => {

    Hoek.assert(data, 'Missing data param');
    Hoek.assert(config, 'Missing config param');
    Hoek.assert(config.secretOrPrivateKey, 'Missing config.secretOrPrivateKey param');

    const settings = InitConfig(config);

    if (settings.sign.promise) {
        return new Promise((resolve, reject) => {

            try {
                const token = JWT.sign(data, settings.secretOrPrivateKey, settings.sign.options);
                resolve(token);
            }
            catch (err) {
                reject(err);
            }
        });
    }

    return JWT.sign(data, settings.secretOrPrivateKey, settings.sign.options);
};
