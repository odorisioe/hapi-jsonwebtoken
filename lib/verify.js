'use strict';

const JWT = require('jsonwebtoken');
const Hoek = require('hoek');
const InitConfig = require('./default');

module.exports = (token , config) => {

    Hoek.assert(token, 'Missing token param');
    Hoek.assert(config, 'Missing config param');
    Hoek.assert(config.secretOrPrivateKey, 'Missing config.secretOrPrivateKey param');

    const settings = InitConfig(config);

    if (settings.verify.promise) {
        return new Promise((resolve, reject) => {

            try {
                const data = JWT.verify(token, settings.secretOrPrivateKey, settings.verify.options);
                resolve(data);
            }
            catch (err) {
                reject(err);
            }
        });
    }

    return JWT.verify(token, settings.secretOrPrivateKey, settings.verify.options);
};
