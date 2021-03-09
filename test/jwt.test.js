const assert = require('assert');
const errors = require('restify-errors');
const jwt = require('jsonwebtoken');
const restifyJWT = require('../lib');

describe('failure tests', function() {
  const req = {};
  const res = {};

  it('should throw if options not sent', function(done) {
    try {
      restifyJWT();
    } catch (e) {
      assert.ok(e);
      assert.strictEqual(e.message, 'secret should be set');
      done();
    }
  });

  it('should throw if no authorization header and credentials are required',
    function() {
      restifyJWT({
        secret: 'shhhh',
        credentialsRequired: true,
      })(req, res, function(err) {
        assert.ok(err);
        assert.strictEqual(err.message, 'No authorization token was found');
      });
    },
  );

  it('support unless skip', function() {
    req.originalUrl = '/index.html';
    restifyJWT({
      secret: 'shhhh',
    }).unless({
      path: '/index.html',
    })(req, res, function(err) {
      assert.ok(!err);
    });
  });

  it('should skip on CORS preflight', function() {
    const corsReq = {};
    corsReq.method = 'OPTIONS';
    corsReq.headers = {
      'access-control-request-headers': 'sasa, sras,  authorization ',
    };
    restifyJWT({secret: 'shhhh'})(corsReq, res, function(err) {
      assert.ok(!err);
    });
  });

  it('should throw if "authorization" does not exist in header ', function() {
    const req = {};
    req.method = 'OPTIONS';
    req.headers = {
      'access-control-request-headers': 'sasa, sras',
    };
    restifyJWT({secret: 'shhhh'})(req, res, function(err) {
      assert.ok(err);
    });
  });

  it('should throw if authorization header is malformed', function() {
    req.headers = {};
    req.headers.authorization = 'wrong';
    restifyJWT({secret: 'shhhh'})(req, res, function(err) {
      assert.ok(err);
      assert.strictEqual(
        err.message,
        'Format is Authorization: Bearer [token] or Jwt [token]',
      );
    });
  });

  it('should throw if authorization header is not Bearer nor JWT', function() {
    req.headers = {};
    req.headers.authorization = 'Basic foobar';
    restifyJWT({secret: 'shhhh'})(req, res, function(err) {
      assert.ok(err);
      assert.strictEqual(err.body.code, 'InvalidCredentials');
    });
  });

  it('should throw if authorization header is not well-formatted jwt',
    function() {
      req.headers = {};
      req.headers.authorization = 'Bearer wrongjwt';
      restifyJWT({secret: 'shhhh'})(req, res, function(err) {
        assert.ok(err);
        assert.strictEqual(err.body.code, 'InvalidCredentials');
      });
    },
  );

  it('should throw if jwt is an invalid json', function() {
    req.headers = {};
    req.headers.authorization = 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.' +
      'eyJpYXQiOjExNTg0MDcxNjksImp0aSI6ImVhZDU4YTk1LWY1NDUtNDA1My04Y2RhLTA0' +
      'ODdjYWIYgTBmMiIsImV4cCI6MTUxMTExMDc4OX0.foo';
    restifyJWT({secret: 'shhhh'})(req, res, function(err) {
      assert.ok(err);
      assert.strictEqual(err.body.code, 'InvalidCredentials');
    });
  });

  it('should throw if authorization header is not valid jwt', function(done) {
    const secret = 'shhhhhh';
    const token = jwt.sign({foo: 'bar'}, secret);

    req.headers = {};
    req.headers.authorization = 'Bearer ' + token;
    restifyJWT({secret: 'different-shhhh'})(req, res, function(err) {
      assert.ok(err);
      assert.strictEqual(err.body.code, 'InvalidCredentials');
      assert.strictEqual(err.jse_cause.message, 'invalid signature');
      done();
    });
  });

  it('should throw if audience is not expected', function(done) {
    const secret = 'shhhhhh';
    const token = jwt.sign({foo: 'bar', aud: 'expected-audience'}, secret);

    req.headers = {};
    req.headers.authorization = 'Bearer ' + token;
    restifyJWT({
      secret: 'shhhhhh',
      audience: 'not-expected-audience',
    })(req, res, function(err) {
      assert.ok(err);
      assert.strictEqual(err.body.code, 'InvalidCredentials');
      assert.strictEqual(
        err.jse_cause.message,
        'jwt audience invalid. expected: not-expected-audience',
      );
      done();
    });
  });

  it('should throw if token is expired', function(done) {
    const secret = 'shhhhhh';
    const token = jwt.sign({foo: 'bar', exp: 1382412921}, secret);

    req.headers = {};
    req.headers.authorization = 'Bearer ' + token;
    restifyJWT({secret: 'shhhhhh'})(req, res, function(err) {
      assert.ok(err);
      assert.strictEqual(err.body.code, 'Unauthorized');
      assert.strictEqual(err.message, 'The token has expired');
      done();
    });
  });

  it('should throw if token issuer is wrong', function(done) {
    const secret = 'shhhhhh';
    const token = jwt.sign({foo: 'bar', iss: 'http://foo'}, secret);

    req.headers = {};
    req.headers.authorization = 'Bearer ' + token;
    restifyJWT({secret: 'shhhhhh', issuer: 'http://wrong'})(req, res, function(err) {
      assert.ok(err);
      assert.strictEqual(err.body.code, 'InvalidCredentials');
      assert.strictEqual(err.jse_cause.message, 'jwt issuer invalid. expected: http://wrong');
      done();
    });
  });

  it('should use errors thrown from custom getToken function', function() {
    /**
     * @throws error InvalidCredentials
     */
    function getTokenThatThrowsError() {
      throw new errors.InvalidCredentialsError('Invalid token!');
    }

    restifyJWT({
      secret: 'shhhhhh',
      getToken: getTokenThatThrowsError,
    })(req, res, function(err) {
      assert.ok(err);
      assert.strictEqual(err.message, 'Invalid token!');
    });
  });


  it('should throw error when signature is wrong', function(done) {
    const secret = 'shhh';
    const token = jwt.sign({foo: 'bar', iss: 'http://www'}, secret);
    // manipulate the token
    const newContent = Buffer.from('{foo: \'bar\', edg: \'ar\'}')
      .toString('base64');
    const splitetToken = token.split('.');
    splitetToken[1] = newContent;
    const newToken = splitetToken.join('.');

    // build request
    req.headers = [];
    req.headers.authorization = 'Bearer ' + newToken;
    restifyJWT({secret: secret})(req, res, function(err) {
      assert.ok(err);
      assert.strictEqual(err.body.code, 'InvalidCredentials');
      assert.strictEqual(err.jse_cause.message, 'invalid token');
      done();
    });
  });
});

describe('work tests', function() {
  let req = {};
  const res = {};

  it('should work if authorization header is valid jwt ("Bearer <token>")',
    function() {
      const secret = 'shhhhhh';
      const token = jwt.sign({foo: 'bar'}, secret);

      req.headers = {};
      req.headers.authorization = 'Bearer ' + token;
      restifyJWT({secret: secret})(req, res, function() {
        assert.strictEqual('bar', req.user.foo);
      });
    },
  );

  it('should work if authorization header is valid jwt ("JWT <token>")',
    function() {
      const secret = 'shhhhhh';
      const token = jwt.sign({foo: 'bar'}, secret);

      req.headers = {};
      req.headers.authorization = 'JWT ' + token;
      restifyJWT({secret: secret})(req, res, function() {
        assert.strictEqual('bar', req.user.foo);
      });
    },
  );

  it('should work if authorization header is valid with a buffer secret',
    function() {
      const secret = Buffer.from(
        'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        'base64',
      );
      const token = jwt.sign({foo: 'bar'}, secret);

      req.headers = {};
      req.headers.authorization = 'Bearer ' + token;
      restifyJWT({secret: secret})(req, res, function() {
        assert.strictEqual('bar', req.user.foo);
      });
    });

  it('should set userProperty if option provided', function() {
    const secret = 'shhhhhh';
    const token = jwt.sign({foo: 'bar'}, secret);

    req.headers = {};
    req.headers.authorization = 'Bearer ' + token;
    restifyJWT({secret: secret, userProperty: 'auth'})(req, res, function() {
      assert.strictEqual('bar', req.auth.foo);
    });
  });

  it('should work if no authorization header and credentials are not required',
    function() {
      req = {};
      restifyJWT({
        secret: 'shhhh',
        credentialsRequired: false,
      })(req, res, function(err) {
        assert(typeof err === 'undefined');
      });
    });

  it('should work if token is expired and credentials are not required',
    function() {
      const secret = 'shhhhhh';
      const token = jwt.sign({foo: 'bar', exp: 1382412921}, secret);

      req.headers = {};
      req.headers.authorization = 'Bearer ' + token;
      restifyJWT({
        secret: secret,
        credentialsRequired: false,
      })(req, res, function(err) {
        assert(typeof err === 'undefined');
        assert(typeof req.user === 'undefined');
      });
    },
  );

  it('should not work if no authorization header', function() {
    req = {};
    restifyJWT({secret: 'shhhh'})(req, res, function(err) {
      assert(typeof err !== 'undefined');
    });
  });

  it('should work with a custom getToken function', function() {
    const secret = 'shhhhhh';
    const token = jwt.sign({foo: 'bar'}, secret);

    req.headers = {};
    req.query = {};
    req.query.token = token;

    /**
     * @param {object} req
     * @return {string | string[] | {}}
     */
    function getTokenFromQuery(req) {
      return req.query.token;
    }

    restifyJWT({
      secret: secret,
      getToken: getTokenFromQuery,
    })(req, res, function() {
      assert.strictEqual('bar', req.user.foo);
    });
  });

  it('should work with a secretCallback function that accepts header argument',
    function() {
      const secret = 'shhhhhh';
      const secretCallback = function(req, headers, payload, cb) {
        assert.strictEqual(headers.alg, 'HS256');
        assert.strictEqual(payload.foo, 'bar');
        process.nextTick(function() {
          return cb(null, secret);
        });
      };
      const token = jwt.sign({foo: 'bar'}, secret);

      req.headers = {};
      req.headers.authorization = 'Bearer ' + token;
      restifyJWT({secret: secretCallback})(req, res, function() {
        assert.strictEqual('bar', req.user.foo);
      });
    });
});
