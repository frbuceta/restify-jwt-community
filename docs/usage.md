---
layout: default
title: Usage
nav_order: 2
permalink: /usage
---

# Usage

The JWT authentication middleware authenticates callers using a JWT.
If the token is valid, `req.user` will be set with the JSON object decoded
to be used by later middleware for authorization and access control.

For example,

```js
const rJWT = require('restify-jwt-community');

app.get('/protected',
  rJWT({secret: 'shhhhhhared-secret'}),
  function(req, res) {
    if (!req.user.admin) return res.send(401);
    res.send(200);
  });
```

You can specify audience and/or issuer as well:

```js
rJWT({ secret: 'shhhhhhared-secret',
  audience: 'http://myapi/protected',
  issuer: 'http://issuer' })
```

> If the JWT has an expiration (`exp`), it will be checked.

If you are using a base64 URL-encoded secret, pass a `Buffer` with `base64` encoding as the secret instead of a string:

```js
rJWT({ secret: new Buffer('shhhhhhared-secret', 'base64') })
```

Optionally you can make some paths unprotected as follows:

```js
app.use(rJWT({ secret: 'shhhhhhared-secret'}).unless({path: ['/token']}));
```

This is especially useful when applying to multiple routes. In the example above, `path` can be a string, a regexp, or an array of any of those.

> For more details on the `.unless` syntax including additional options, please see [express-unless](https://github.com/jfromaniello/express-unless).

This module also support tokens signed with public/private key pairs. Instead of a secret, you can specify a Buffer with the public key

```js
const publicKey = fs.readFileSync('/pat/to/public.pub');

rJWT({ secret: publicKey });
```

By default, the decoded token is attached to `req.user` but can be configured with the `requestProperty` option.


```js
rJWT({ secret: publicKey, requestProperty: 'auth' });
```

A custom function for extracting the token from a request can be specified with
the `getToken` option. This is useful if you need to pass the token through a
query parameter or a cookie. You can throw an error in this function and it will
be handled by `restify-jwt-community`.

```js
app.use(rJWT({
  secret: 'hello world !',
  credentialsRequired: false,
  getToken: function fromHeaderOrQuerystring (req) {
    if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
        return req.headers.authorization.split(' ')[1];
    } else if (req.query && req.query.token) {
      return req.query.token;
    }
    return null;
  }
}));
```

### Multi-tenancy
If you are developing an application in which the secret used to sign tokens is not static, you can provide a callback function as the `secret` parameter. The function has the signature: `function(req, payload, done)`:
* `req` (`Object`) - The restify `request` object.
* `payload` (`Object`) - An object with the JWT claims.
* `done` (`Function`) - A function with signature `function(err, secret)` to be invoked when the secret is retrieved.
  * `err` (`Any`) - The error that occurred.
  * `secret` (`String`) - The secret to use to verify the JWT.

For example, if the secret varies based on the [JWT issuer](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html#issDef):
```js
const rJWT = require('restify-jwt-community');
const data = require('./data');
const utilities = require('./utilities');

const secretCallback = function(req, payload, done){
  const issuer = payload.iss;

  data.getTenantByIdentifier(issuer, function(err, tenant){
    if (err) { return done(err); }
    if (!tenant) { return done(new Error('missing_secret')); }

    const secret = utilities.decrypt(tenant.secret);
    done(null, secret);
  });
};

app.get('/protected',
  rJWT({secret: secretCallback}),
  function(req, res) {
    if (!req.user.admin) return res.send(401);
    res.send(200);
  });
```

### Revoked tokens
It is possible that some tokens will need to be revoked so they cannot be used any longer. You can provide a function as the `isRevoked` option. The signature of the function is `function(req, payload, done)`:
* `req` (`Object`) - The restify `request` object.
* `payload` (`Object`) - An object with the JWT claims.
* `done` (`Function`) - A function with signature `function(err, revoked)` to be invoked once the check to see if the token is revoked or not is complete.
  * `err` (`Any`) - The error that occurred.
  * `revoked` (`Boolean`) - `true` if the JWT is revoked, `false` otherwise.

For example, if the `(iss, jti)` claim pair is used to identify a JWT:
```js
const rJWT = require('restify-jwt-community');
const data = require('./data');
const utilities = require('./utilities');

const isRevokedCallback = function(req, payload, done){
  const issuer = payload.iss;
  const tokenId = payload.jti;

  data.getRevokedToken(issuer, tokenId, function(err, token){
    if (err) { return done(err); }
    return done(null, !!token);
  });
};

app.get('/protected',
  rJWT({secret: 'shhhhhhared-secret', isRevoked: isRevokedCallback}),
  function(req, res) {
    if (!req.user.admin) return res.send(401);
    res.send(200);
  });
```

### Error handling

The default behavior is to throw an error when the token is invalid, so you can add your custom logic to manage unauthorized access as follows:


```js
app.use(function (err, req, res, next) {
  if (err.name === 'UnauthorizedError') {
    res.send(401, 'invalid token...');
  }
});
```

You might want to use this module to identify registered users without preventing unregistered clients to access to some data, you
can do it using the option _credentialsRequired_:

```js
app.use(jwt({
  secret: 'hello world !',
  credentialsRequired: false
}));
```
