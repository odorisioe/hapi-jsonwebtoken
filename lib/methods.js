'use strict';

const JWT = require('jsonwebtoken');
const Hoek = require('hoek');
const ApplyToDefaults = require('./defaults');

/**
 *
 *
 */
exports.sign = (data, config) => {

    Hoek.assert(data, 'Missing data param');
    Hoek.assert(config, 'Missing config param');
    Hoek.assert(config.secretOrPrivateKey, 'Missing config.secretOrPrivateKey param');

    const settings = ApplyToDefaults(config);

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


/**
 *
 *
 */
exports.decode = (token, config) => {

    Hoek.assert(token, 'Missing token param');

    const settings = ApplyToDefaults(config);

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


/**
 *
 *
 */
exports.verify = (token, config) => {

    Hoek.assert(token, 'Missing token param');
    Hoek.assert(config, 'Missing config param');
    Hoek.assert(config.secretOrPrivateKey, 'Missing config.secretOrPrivateKey param');

    const settings = ApplyToDefaults(config);

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
