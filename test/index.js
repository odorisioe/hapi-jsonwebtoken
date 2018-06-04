'use strict';

const Code = require('code');
const Hoek = require('hoek');
const HapiJWT = require('../');
const Hapi = require('hapi');
const Lab = require('lab');

const { describe, it } = exports.lab = Lab.script();
const expect = Code.expect;

const internals = {};

/**
 * Tests
 *
 */
describe('hapi-jsonwebtoken', () => {


    it('Encode, decode & verify - valid token', () => {

        const config = {
            secretOrPrivateKey: 's3cr3t'
        };
        const user = internals.users[1];
        const token = HapiJWT.sign(user, config);
        const decoded = HapiJWT.decode(token);

        expect(decoded.id).to.equal(user.id);
        expect(decoded.scope).to.equal(user.scope);
        expect(decoded.username).to.equal(user.username);

        const verified = HapiJWT.verify(token, config);

        expect(verified.id).to.equal(user.id);
        expect(verified.scope).to.equal(user.scope);
        expect(verified.username).to.equal(user.username);
    });


    it('Encode, decode & verify - valid token with config', () => {

        const config = Hoek.clone(internals.config[1]);
        const user = internals.users[2];
        const token = HapiJWT.sign(user, config);

        const decoded = HapiJWT.decode(token);

        expect(decoded.id).to.equal(user.id);
        expect(decoded.scope).to.equal(user.scope);
        expect(decoded.username).to.equal(user.username);

        const verified = HapiJWT.verify(token, config);

        expect(verified.id).to.equal(user.id);
        expect(verified.scope).to.equal(user.scope);
        expect(verified.username).to.equal(user.username);

    });


    it('Encode, decode & verify - expired token with config', () => {

        const config = Hoek.clone(internals.config[1]);
        config.sign.options.expiresIn = -10;
        const user = internals.users[3];
        const token = HapiJWT.sign(user, config);

        const decoded = HapiJWT.decode(token);

        expect(decoded.id).to.equal(user.id);
        expect(decoded.scope).to.equal(user.scope);
        expect(decoded.username).to.equal(user.username);

        let error;
        try {
            HapiJWT.verify(token, config);
        }
        catch (err) {
            error = err;
        }

        expect(error.name).to.equal('TokenExpiredError');
    });


    it('Encode, decode & verify (w/ promises) - valid token', async () => {

        const config = {
            secretOrPrivateKey: 's3cr3t',
            sign: {
                promise: true
            },
            decode: {
                promise: true
            },
            verify: {
                promise: true
            }
        };
        const user = internals.users[1];
        const token = await HapiJWT.sign(user, config)
            .then((result) => {

                return result;
            });
        const decoded = await HapiJWT.decode(token, config)
            .then((result) => {

                return result;
            });

        expect(decoded.id).to.equal(user.id);
        expect(decoded.scope).to.equal(user.scope);
        expect(decoded.username).to.equal(user.username);

        const verified = await HapiJWT.verify(token, config)
            .then((result) => {

                return result;
            });

        expect(verified.id).to.equal(user.id);
        expect(verified.scope).to.equal(user.scope);
        expect(verified.username).to.equal(user.username);
    });


    it('Encode, decode & verify (w/ promises) - valid token with config', async () => {

        const config = Hoek.clone(internals.config[1]);
        config.sign.promise = true;
        config.decode.promise = true;
        config.verify.promise = true;

        const user = internals.users[2];
        const token = await HapiJWT.sign(user, config)
            .then((result) => {

                return result;
            });
        const decoded = await HapiJWT.decode(token, config)
            .then((result) => {

                return result;
            });

        expect(decoded.payload.id).to.equal(user.id);
        expect(decoded.payload.scope).to.equal(user.scope);
        expect(decoded.payload.username).to.equal(user.username);

        const verified = await HapiJWT.verify(token, config)
            .then((result) => {

                return result;
            });

        expect(verified.id).to.equal(user.id);
        expect(verified.scope).to.equal(user.scope);
        expect(verified.username).to.equal(user.username);
    });


    it('Encode, decode & verify (w/ promises) - invalid sign algorithm', async () => {

        const config = Hoek.clone(internals.config[1]);
        config.sign.promise = true;
        config.sign.options.algorithm = 'RS256X';
        config.decode.promise = true;

        const user = internals.users[3];
        const token = await HapiJWT.sign(user, config)
            .then((result) => {

                return result;
            })
            .catch((err) => {

                return err;
            });

        expect(token.name).to.equal('Error');
    });


    it('Encode, decode & verify (w/ promises) - expired token with config', async () => {

        const config = Hoek.clone(internals.config[1]);
        config.sign.promise = true;
        config.sign.options.expiresIn = -10;
        config.decode.promise = true;
        config.verify.promise = true;

        const user = internals.users[2];
        const token = await HapiJWT.sign(user, config)
            .then((result) => {

                return result;
            });
        const decoded = await HapiJWT.decode(token, config)
            .then((result) => {

                return result;
            });

        expect(decoded.payload.id).to.equal(user.id);
        expect(decoded.payload.scope).to.equal(user.scope);
        expect(decoded.payload.username).to.equal(user.username);

        const error = await HapiJWT.verify(token, config)
            .then((result) => {

                return result;
            })
            .catch((err) => {

                return err;
            });

        expect(error.name).to.equal('TokenExpiredError');
    });


    it('Auth plugin - unauthorized (no token)', async () => {

        const server = await internals.hapi();
        server.auth.strategy('jwt', 'hapi-jsonwebtoken', internals.config[1]);

        server.route({
            method: 'GET',
            path: '/',
            handler: function (request, h) {

                return 'OK';
            },
            options: {
                auth: 'jwt'
            }
        });

        const request = { method: 'GET', url: '/' };
        const res = await server.inject(request);

        expect(res.result).not.equal('OK');
        expect(res.statusCode).to.equal(401);
    });


    it('Auth plugin - unauthorized (no scope)', async () => {

        const user = internals.users[3];
        const config = Hoek.clone(internals.config[1]);
        const token = await HapiJWT.sign(user, config);

        const server = await internals.hapi();
        server.auth.strategy('jwt', 'hapi-jsonwebtoken', config);

        server.route({
            method: 'GET',
            path: '/',
            handler: function (request, h) {

                return 'OK';
            },
            options: {
                auth: {
                    strategy: 'jwt',
                    scope: ['admin']
                }
            }
        });

        const request = { method: 'GET', url: '/', headers: { authorization: 'Bearer ' + token } };
        const res = await server.inject(request);

        expect(res.result).not.equal('OK');
        expect(res.statusCode).to.equal(403);
    });


    it('Auth plugin - unauthorized (invalid token)', async () => {

        const user = internals.users[3];
        const config = Hoek.clone(internals.config[1]);

        const server = await internals.hapi();
        server.auth.strategy('jwt', 'hapi-jsonwebtoken', config);

        const token = await server.methods.jwtSign(user);

        server.route({
            method: 'GET',
            path: '/',
            handler: function (request, h) {

                return 'OK';
            },
            options: {
                auth: {
                    strategy: 'jwt',
                    scope: ['user']
                }
            }
        });

        const request = { method: 'GET', url: '/', headers: { authorization: 'Bearer ' + 'abcde' + token.slice(5) } };
        const res = await server.inject(request);

        expect(res.result).not.equal('OK');
        expect(res.statusCode).to.equal(401);
    });


    it('Auth plugin - unauthorized (invalid user)', async () => {

        const user = internals.users[4];
        const config = Hoek.clone(internals.config[1]);

        const server = await internals.hapi();
        server.auth.strategy('jwt', 'hapi-jsonwebtoken', config);

        const token = server.methods.jwtSign(user);

        server.route({
            method: 'GET',
            path: '/',
            handler: function (request, h) {

                return 'OK';
            },
            options: {
                auth: {
                    strategy: 'jwt',
                    scope: ['user']
                }
            }
        });

        const request = { method: 'GET', url: '/', headers: { authorization: 'Bearer ' + token } };
        const res = await server.inject(request);

        expect(res.result).not.equal('OK');
        expect(res.statusCode).to.equal(401);
    });


    it('Auth plugin - unauthorized (expired token)', async () => {

        const user = internals.users[1];
        const config = Hoek.clone(internals.config[1]);
        config.sign.options.expiresIn = -10;

        const server = await internals.hapi();
        server.auth.strategy('jwt', 'hapi-jsonwebtoken', config);

        const token = server.methods.jwtSign(user);

        server.route({
            method: 'GET',
            path: '/',
            handler: function (request, h) {

                return 'OK';
            },
            options: {
                auth: {
                    strategy: 'jwt',
                    scope: ['admin']
                }
            }
        });

        const request = { method: 'GET', url: '/', headers: { authorization: 'Bearer ' + token } };
        const res = await server.inject(request);

        expect(res.result).not.equal('OK');
        expect(res.statusCode).to.equal(401);
    });


    it('Auth plugin - bad implementation (no credentials object)', async () => {

        const user = internals.users[3];
        const config = Hoek.clone(internals.config[3]);

        const server = await internals.hapi({
            debug: false
        });
        server.auth.strategy('jwt', 'hapi-jsonwebtoken', config);

        const token = server.methods.jwtSign(user);

        server.route({
            method: 'GET',
            path: '/',
            handler: function (request, h) {

                return 'OK';
            },
            options: {
                auth: 'jwt'
            }
        });

        const request = { method: 'GET', url: '/', headers: { authorization: 'Bearer ' + token } };
        const res = await server.inject(request);

        expect(res.result).not.equal('OK');
        expect(res.statusCode).to.equal(500);
    });


    it('Auth plugin - bad implementation (false value on credentials object)', async () => {

        const user = internals.users[3];
        const config = Hoek.clone(internals.config[4]);

        const server = await internals.hapi({ debug: false });
        server.auth.strategy('jwt', 'hapi-jsonwebtoken', config);

        const token = server.methods.jwtSign(user);

        server.route({
            method: 'GET',
            path: '/',
            handler: function (request, h) {

                return 'OK';
            },
            options: {
                auth: 'jwt'
            }
        });

        const request = { method: 'GET', url: '/', headers: { authorization: 'Bearer ' + token } };
        const res = await server.inject(request);

        expect(res.result).not.equal('OK');
        expect(res.statusCode).to.equal(500);
    });


    it('Auth plugin - authorized', async () => {

        const user = internals.users[1];
        const config = Hoek.clone(internals.config[1]);

        const server = await internals.hapi();
        server.auth.strategy('jwt', 'hapi-jsonwebtoken', config);

        const token = server.methods.jwtSign(user);

        server.route({
            method: 'GET',
            path: '/',
            handler: function (request, h) {

                return 'OK';
            },
            options: {
                auth: {
                    strategy: 'jwt',
                    scope: ['admin']
                }
            }
        });

        const request = { method: 'GET', url: '/', headers: { authorization: 'Bearer ' + token } };
        const res = await server.inject(request);

        expect(res.result).to.equal('OK');
        expect(res.statusCode).to.equal(200);
    });


    it('Auth plugin (w/ promises) - authorized', async () => {

        const user = internals.users[1];
        const config = Hoek.clone(internals.config[1]);
        config.sign.promise = true;
        config.decode.promise = true;
        config.verify.promise = true;

        const server = await internals.hapi();
        server.auth.strategy('jwt', 'hapi-jsonwebtoken', config);

        const token = await server.methods.jwtSign(user)
            .then((result) => {

                return result;
            });

        server.route({
            method: 'GET',
            path: '/',
            handler: function (request, h) {

                return 'OK';
            },
            options: {
                auth: {
                    strategy: 'jwt',
                    scope: ['admin']
                }
            }
        });

        const request = { method: 'GET', url: '/', headers: { authorization: 'Bearer ' + token } };
        const res = await server.inject(request);

        expect(res.result).to.equal('OK');
        expect(res.statusCode).to.equal(200);
    });


    it('Auth plugin - authorized (two strategies)', async () => {

        const userOne = internals.users[1];
        const configOne = Hoek.clone(internals.config[1]);
        configOne.serverMethods.prefix = 'jwtOne';

        const userTwo = internals.users[2];
        const configTwo = Hoek.clone(internals.config[2]);
        configTwo.serverMethods.prefix = 'jwtTwo';

        const server = await internals.hapi();
        server.auth.strategy('jwtOne', 'hapi-jsonwebtoken', configOne);
        server.auth.strategy('jwtTwo', 'hapi-jsonwebtoken', configTwo);

        const tokenOne = server.methods.jwtOneSign(userOne);
        const tokenTwo = server.methods.jwtTwoSign(userTwo);

        server.route({
            method: 'GET',
            path: '/endpointOne',
            handler: function (request, h) {

                return 'OkOne';
            },
            options: {
                auth: 'jwtOne'
            }
        });

        server.route({
            method: 'GET',
            path: '/endpointTwo',
            handler: function (request, h) {

                return 'OkTwo';
            },
            options: {
                auth: 'jwtTwo'
            }
        });

        server.route({
            method: 'GET',
            path: '/endpointThree',
            handler: function (request, h) {

                return 'OkThree';
            },
            options: {
                auth: {
                    strategies: ['jwtOne', 'jwtTwo']
                }
            }
        });

        const requestOne = { method: 'GET', url: '/endpointOne', headers: { authorization: 'Bearer ' + tokenOne } };
        const resOne = await server.inject(requestOne);

        expect(resOne.result).to.equal('OkOne');
        expect(resOne.statusCode).to.equal(200);

        const requestTwo = { method: 'GET', url: '/endpointTwo', headers: { authorization: 'Bearer ' + tokenTwo } };
        const resTwo = await server.inject(requestTwo);

        expect(resTwo.result).to.equal('OkTwo');
        expect(resTwo.statusCode).to.equal(200);

        const requestThree = { method: 'GET', url: '/endpointTwo', headers: { authorization: 'Bearer ' + tokenOne } };
        const resThree = await server.inject(requestThree);

        expect(resThree.result).not.equal('OkOne');
        expect(resThree.statusCode).to.equal(401);

        const requestFour = { method: 'GET', url: '/endpointOne', headers: { authorization: 'Bearer ' + tokenTwo } };
        const resFour = await server.inject(requestFour);

        expect(resFour.result).not.equal('OkOne');
        expect(resFour.statusCode).to.equal(401);

        const requestFive = { method: 'GET', url: '/endpointThree', headers: { authorization: 'Bearer ' + tokenOne } };
        const resFive = await server.inject(requestFive);

        expect(resFive.result).to.equal('OkThree');
        expect(resFive.statusCode).to.equal(200);

        const requestSix = { method: 'GET', url: '/endpointThree', headers: { authorization: 'Bearer ' + tokenTwo } };
        const resSix = await server.inject(requestSix);

        expect(resSix.result).to.equal('OkThree');
        expect(resSix.statusCode).to.equal(200);
    });


    it('Auth plugin - disable server methods', async () => {

        const config = Hoek.clone(internals.config[1]);
        config.serverMethods.enable = false;

        const server = await internals.hapi();
        server.auth.strategy('jwt', 'hapi-jsonwebtoken', config);

        expect(server.methods.jwtSign).to.equal(undefined);
        expect(server.methods.jwtDecode).to.equal(undefined);
        expect(server.methods.jwtVerify).to.equal(undefined);
    });


    it('Auth plugin - server methods', async () => {

        const user = internals.users[1];
        const config = Hoek.clone(internals.config[1]);

        const server = await internals.hapi();
        server.auth.strategy('jwt', 'hapi-jsonwebtoken', config);

        const token = server.methods.jwtSign(user);

        const decoded = server.methods.jwtDecode(token, { decode: { complete: true } });

        expect(decoded.payload.id).to.equal(user.id);
        expect(decoded.payload.username).to.equal(user.username);

        const verified = server.methods.jwtVerify(token);

        expect(verified.id).to.equal(user.id);
        expect(verified.username).to.equal(user.username);
    });
});




/**
 * Internals
 *
 *
 */
internals.config = {
    1: {
        secretOrPrivateKey: '#Config01!',
        serverMethods: {},
        sign: {
            promise: false,
            options: { // https://github.com/auth0/node-jsonwebtoken#jwtsignpayload-secretorprivatekey-options-callback
                expiresIn: '1h'
            }
        },
        verify: {
            promise: false,
            options: { // https://github.com/auth0/node-jsonwebtoken#jwtverifytoken-secretorpublickey-options-callback
            }
        },
        decode: {
            promise: false,
            options: { // https://github.com/auth0/node-jsonwebtoken#jwtdecodetoken--options
                complete: true
            }
        },
        validate: (request, payload, h) => {

            const user = internals.users[payload.id];

            if (!user) {
                return { credentials: null, isValid: false };
            }

            return {
                isValid: user.valid,
                credentials: user
            };
        }
    },
    2: {
        secretOrPrivateKey: '#Config02!',
        serverMethods: {},
        validate: (request, payload, h) => {

            const user = internals.users[payload.id];

            if (!user) {
                return { credentials: null, isValid: false };
            }

            return {
                isValid: user.valid,
                credentials: user
            };
        }
    },
    3: {
        secretOrPrivateKey: '#Config03!',
        validate: (request, payload, h) => {

            const user = internals.users[payload.id];

            if (!user) {
                return { credentials: null, isValid: false };
            }

            return {
                isValid: user.valid,
                credentials: user.valid
            };
        }
    },
    4: {
        secretOrPrivateKey: '#Config03!',
        validate: (request, payload, h) => {

            const user = internals.users[payload.id];

            if (!user) {
                return { credentials: null, isValid: false };
            }

            return {
                isValid: user.valid,
                credentials: false
            };
        }
    }
};

internals.hapi = async (options) => {

    const server = Hapi.server(options);
    await server.register(require('../').plugin);
    return server;
};


internals.users = {
    1: {
        id: 1,
        username: 'axl',
        valid: true,
        scope: ['admin']
    },
    2: {
        id: 2,
        username: 'slash',
        valid: true,
        scope: ['admin']
    },
    3: {
        id: 3,
        username: 'duff',
        valid: true,
        scope: ['user']
    },
    4: {
        id: 4,
        username: 'izzy',
        valid: false,
        scope: ['user']
    }
};
