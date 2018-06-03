'use strict';

const JWT = require('jsonwebtoken');
const Hoek = require('hoek');
const InitConfig = require('./default');

module.exports = (token, config) => {

    Hoek.assert(token, 'Missing token param');

    const settings = InitConfig(config);

    if (settings.decode.promise) {
        return new Promise((resolve, reject) => {

            try {
                const payload = JWT.decode(token, settings.decode.options);
                resolve(payload);
            }
            catch (err) {
                reject(err);
            }
        });
    }

    return JWT.decode(token, settings.decode.options);
};
