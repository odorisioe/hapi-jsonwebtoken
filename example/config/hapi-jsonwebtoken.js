'use strict';

const Users = require('./users');

module.exports = {
    secretOrPrivateKey: 's3cr3t',
    sign: {},
    decode: {},
    verify: {},
    getToken: (request) => {

        return request.headers.authorization;
    },
    validate: (request, payload, h) => {

        const user = Users[payload.id];

        if (!user) {
            return { credentials: null, isValid: false };
        }

        return {
            isValid: user.isActive,
            credentials: { id: user.id, name: user.name }
        };
    }
};
