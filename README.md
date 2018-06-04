# hapi-jsonwebtoken
JsonWebToken implementation for Hapi.js v17+ with authentication plugin and server methods.

This library provides a simple and easy way to integrate [node-jsonwebtoken](https://github.com/auth0/node-jsonwebtoken) in your code using one configuration object for each authentication strategy.


## Installation
```bash
$ npm install --save hapi-jsonwebtoken
```

## Usage
### Authentication plugin
The *hapi-jsonwebtoken* library contains a plugin to create auth strategies.
```javascript
...
const HapiJWT = require('hapi-jsonwebtoken');
const HapiJWTConfig = require('./config/jsonwebtoken');
...
await server.register(HapiJWT.plugin);
server.auth.strategy('jwt', 'hapi-jsonwebtoken', HapiJWTConfig);
server.auth.default('jwt');
...
```
[See full example](example/server.js)

### Configuration object
Each strategy needs to have its configuration object. It is recommended to create a new file with all the configuration to include and use in your code.
```javascript
const HapiJWTConfig = require('./config/jsonwebtoken');
```
The object can take following keys:
- **`secretOrPrivateKey`** (required)
- **`serverMethods`**:
	- **`enable`** set to `false` to not add the server methods. Default is `true`.
	- **`prefix`**:  use to define the beginning of server method names . Default is `"jwt"` *(functions: jwtSign jwtVerify, jwtDecode)*
- **`sign`**:
	- **`promise`**: set to `true` to return a promise. Default is `false`.
	- **`options`**: options of method sign() [docs](https://github.com/auth0/node-jsonwebtoken#jwtsignpayload-secretorprivatekey-options-callback). Default is `null`.
- **`verify`**:
	- **`promise`**: set to `true` to return a promise. Default is `false`
	- **`options`**: options of method verify() [docs](https://github.com/auth0/node-jsonwebtoken#jwtverifytoken-secretorpublickey-options-callback). Default is `null`.
- **`decode`**:
	- **`promise`**: set to `true` to return a promise. Default is `false`
	- **`options`**: options of method decode() on the  [docs](https://github.com/auth0/node-jsonwebtoken#jwtdecodetoken--options). Default is `null`.
- **`getToken: function(request)`**:  (optional) custom function to get the token. By default, it checks *request.headers.authorization* and removes the string "Bearer " at the beginning.
- **`validate: function(request, payload, h)`**: (required) a validation function to check the user credentials.
	- returns an object `{ isValid, credentials }`
		- `isValid` - `true` if username was found and match with payload data, otherwise `false`.
		- `credentials` -  a credentials object passed back to the application in `request.auth.credentials`.

### Server methods
When a new *hapi-jsonwebtoken* strategy is added, three methods will be included on the server unless `serverMethods.enable = false`. These methods will use the same configuration object used for the plugin.

#### server.methods.jwtSign(data, [config])

#### server.methods.jwtDecode(token, [config])

#### server.methods.jwtSign(token, [config])

> The param **config** is optional and only allows to overwrite keys of the initial configuration.

> The name of the functions can be different depending of the value of `serverMethods.prefix`

> The functions can return or different content depending of the value of `sign`, `decode` and `verify`.

## More
### Define multiple auth strategies
Each strategy needs to use a different configuration object and the value of `serverMethods.prefix` must be different to avoid duplicated server methods.
```javascript
...
const HapiJWT = require('hapi-jsonwebtoken');
// Configuration can be included in the same config file
const HapiJWTConfig = require('./config/hapi-jsonwebtoken');
...
await server.register(HapiJWT.plugin);
server.auth.strategy('jwtInternal', 'hapi-jsonwebtoken', HapiJWTConfig.internal);
server.auth.strategy('jwtPublic', 'hapi-jsonwebtoken', HapiJWTConfig.public);
server.auth.default('jwtPublic');
...
```
