'use strict';

const Hoek = require('hoek');

const defaults = {
    getToken: (request) => {

        const header = request.headers.authorization;

        if (header) {
            return header.slice(7); // Remove "bearer "
        }

        return null;
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
