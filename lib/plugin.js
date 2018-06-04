'use strict';

const Boom = require('boom');
const Hoek = require('hoek');
const HapiJwtMethods = require('./methods');
const ApplyToDefaults = require('./defaults');
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

    const settings = ApplyToDefaults(options);

    if (settings.serverMethods.enable) {
        internals.addServerMethods(server, settings);
    }

    const scheme = {
        authenticate: async (request, h) => {

            const token = await settings.getToken(request);

            if (!token) {
                throw Boom.unauthorized(null, 'bearer');
            }

            const VerifyFnName = settings.serverMethods.prefix + 'Verify';
            let payload;
            try {
                payload = await server.methods[VerifyFnName](token, { verify: { promise: false } });
            }
            catch (err) {
                payload = null;
            }

            if (!payload) {
                throw Boom.unauthorized(null, 'bearer');
            }

            const { isValid, credentials } = await settings.validate(request, payload, h);

            if (!isValid) {
                throw Boom.unauthorized(null, 'beader');
            }

            if (!credentials || typeof credentials !== 'object') {
                throw Boom.badImplementation('Bad credentials received for hapi-jsonwebtoken auth validation');
            }

            return h.authenticated({ credentials });
        }
    };

    return scheme;
};


internals.addServerMethods = (server, settings) => {

    const prefix = settings.serverMethods.prefix;

    const mergeWithSettings = (newSettings) => {

        if (!newSettings) {
            return settings;
        }

        return Hoek.applyToDefaults(settings, newSettings);
    };

    server.method(prefix + 'Sign', (data, config) => {

        return HapiJwtMethods.sign(data, mergeWithSettings(config));
    }, {});

    server.method(prefix + 'Verify', (token, config) => {

        return HapiJwtMethods.verify(token, mergeWithSettings(config));
    }, {});

    server.method(prefix + 'Decode', (token, config) => {

        return HapiJwtMethods.decode(token, mergeWithSettings(config));

    }, {});

};
