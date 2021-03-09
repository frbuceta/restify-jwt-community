const assert = require('assert');
const jwt = require('jsonwebtoken');
const restifyJWT = require('../lib');

describe('revoked jwts', function() {
  const secret = 'shhhhhh';

  const revokedId = '1234';

  const middleware = restifyJWT({
    secret: secret,
    isRevoked: function(req, payload, done) {
      done(null, payload.jti && payload.jti === revokedId);
    },
  });

  it('should throw if token is revoked', function() {
    const req = {};
    const res = {};
    const token = jwt.sign({jti: revokedId, foo: 'bar'}, secret);

    req.headers = {};
    req.headers.authorization = 'Bearer ' + token;

    middleware(req, res, function(err) {
      assert.ok(err);
      assert.strictEqual(err.body.code, 'Unauthorized');
      assert.strictEqual(err.message, 'The token has been revoked.');
    });
  });

  it('should work if token is not revoked', function() {
    const req = {};
    const res = {};
    const token = jwt.sign({jti: '1233', foo: 'bar'}, secret);

    req.headers = {};
    req.headers.authorization = 'Bearer ' + token;

    middleware(req, res, function() {
      assert.strictEqual('bar', req.user.foo);
    });
  });

  it('should throw if error occurs checking if token is revoked', function() {
    const req = {};
    const res = {};
    const token = jwt.sign({jti: revokedId, foo: 'bar'}, secret);

    req.headers = {};
    req.headers.authorization = 'Bearer ' + token;

    restifyJWT({
      secret: secret,
      isRevoked: function(req, payload, done) {
        done(new Error('An error ocurred'));
      },
    })(req, res, function(err) {
      assert.ok(err);
      assert.strictEqual(err.message, 'An error ocurred');
    });
  });
});
