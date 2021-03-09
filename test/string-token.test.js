const assert = require('assert');
const jwt = require('jsonwebtoken');
const restifyJWT = require('../lib');

describe('string tokens', function() {
  const req = {};
  const res = {};

  it('should work with a valid string token', function() {
    const secret = 'shhhhhh';
    const token = jwt.sign('foo', secret);

    req.headers = {};
    req.headers.authorization = 'Bearer ' + token;
    restifyJWT({secret: secret})(req, res, function() {
      assert.strictEqual('foo', req.user);
    });
  });
});
