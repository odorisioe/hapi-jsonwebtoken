'use strict';

const Hapi = require('hapi');
const HapiJWT = require('../');
const HapiJWTConfig = require('./config/jsonwebtoken');
const Users = require('./config/users');

const main = async () => {

    const server = Hapi.server({ port: 4000 });

    await server.register(HapiJWT.plugin);
    server.auth.strategy('jwt', 'hapi-jsonwebtoken', HapiJWTConfig);
    server.auth.default('jwt');

    server.route({
        method: 'GET',
        path: '/',
        handler: (request, h) => {

            return 'Auth OK';
        }
    });

    server.route({
        method: 'GET',
        path: '/getValidUserToken',
        handler: (request, h) => {

            return request.server.methods.jwtSign(Users[1]);
        },
        options: {
            auth: false
        }
    });

    server.route({
        method: 'GET',
        path: '/getInvalidUserToken',
        handler: (request, h) => {

            return request.server.methods.jwtSign(Users[2]);
        },
        options: {
            auth: false
        }
    });

    server.route({
        method: 'GET',
        path: '/decodeToken',
        handler: (request, h) => {

            const token = request.headers.authorization;
            return request.server.methods.jwtDecode(token);
        },
        options: {
            auth: false
        }
    });

    await server.start();
    return server;
};

main()
    .then((server) => {

        console.log(`Server listening on ${server.info.uri}`);
    })
    .catch((err) => {

        console.error(err);
        process.exit(1);
    });
