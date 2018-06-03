'use strict';

const Boom = require('boom');
const Hoek = require('hoek');
const VerifyJWT = require('./verify');
const InitConfig = require('./default');
const internals = {};


exports.plugin = {
    pkg: require('../package.json'),
    name: 'hapi-jsonwebtoken',
    register: (server, options) => {

        server.auth.scheme('hapi-jsonwebtoken', internals.implementation);
    }
};


internals.implementation = (server, options) => {

    Hoek.assert(options, 'Missing auth strategy options');
    Hoek.assert(options.secretOrPrivateKey, 'Missing auth strategy secretOrPrivateKey option');
    Hoek.assert(typeof options.validate === 'function', 'options.validate must be a valid function');

    const settings = InitConfig(options);

    const scheme = {
        authenticate: async (request, h) => {

            const token = await settings.getToken(request);

            if (!token) {
                throw Boom.unauthorized(null, 'bearer');
            }

            let payload;
            try {
                payload = await VerifyJWT(token, settings);
            }
            catch (err) {
                payload = null;
            }

            if (!payload) {
                throw Boom.unauthorized(null, 'bearer');
            }

            const { isValid, credentials } = await settings.validate(request, payload, h);
            // const { isValid, credentials, response } = await settings.validate(request, payload, h);

            // @TODO check if "response" can be removed
            // if (response !== undefined) {
            //     return h.response(response).takeover();
            // }

            if (!isValid) {
                throw Boom.unauthorized('Inactive user', 'beader');
            }

            return h.authenticated({ credentials });
        }
    };

    return scheme;
};
