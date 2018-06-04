'use strict';

const Hoek = require('hoek');

const defaults = {
    getToken: (request) => {

        const header = request.headers.authorization;

        // Remove 'bearer '
        if (header && header.substring(0, 7).toLowerCase() === 'bearer ') {
            return header.slice(7);
        }

        return null;
    },
    serverMethods: {
        enable: true,
        prefix: 'jwt'
    },
    sign: {
        promise: false
    },
    decode: {
        promise: false
    },
    verify: {
        promise: false
    }
};

module.exports = (config) => {

    if (!config) {
        return defaults;
    }

    return Hoek.applyToDefaults(defaults, config);
};
