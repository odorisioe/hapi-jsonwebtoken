'use strict';

const Methods = require('./lib/methods');
module.exports = {
    plugin: require('./lib/plugin'),
    sign: Methods.sign,
    verify: Methods.verify,
    decode: Methods.decode
};
