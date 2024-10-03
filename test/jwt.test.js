const errors = require('restify-errors');
const jwt = require('jsonwebtoken');
const restifyJWT = require('../lib');

describe('failure tests', () => {
  const req = {};
  const res = {};

  it('should throw if options not sent', () => {
    expect(() => {
      restifyJWT();
    }).toThrow('secret should be set');
  });

  it('should throw if no authorization header and credentials are required', async () => {
    const err = await new Promise((resolve) => {
      restifyJWT({ secret: 'shhhh', credentialsRequired: true })(req, res, (error) => {
        resolve(error);
      });
    });
    expect(err).toBeDefined();
    expect(err.message).toBe('No authorization token was found');
  });

  it('support unless skip', async () => {
    req.originalUrl = '/index.html';
    const err = await new Promise((resolve) => {
      restifyJWT({ secret: 'shhhh' }).unless({ path: '/index.html' })(req, res, (error) => {
        resolve(error);
      });
    });
    expect(err).toBeUndefined();
  });

  it('should skip on CORS preflight', async () => {
    const corsReq = { method: 'OPTIONS', headers: { 'access-control-request-headers': 'sasa, sras, authorization' } };
    const err = await new Promise((resolve) => {
      restifyJWT({ secret: 'shhhh' })(corsReq, res, (error) => {
        resolve(error);
      });
    });
    expect(err).toBeUndefined();
  });

  it('should throw if "authorization" does not exist in header', async () => {
    req.method = 'OPTIONS';
    req.headers = { 'access-control-request-headers': 'sasa, sras' };
    const err = await new Promise((resolve) => {
      restifyJWT({ secret: 'shhhh' })(req, res, (error) => {
        resolve(error);
      });
    });
    expect(err).toBeDefined();
  });

  it('should throw if authorization header is malformed', async () => {
    req.headers = { authorization: 'wrong' };
    const err = await new Promise((resolve) => {
      restifyJWT({ secret: 'shhhh' })(req, res, (error) => {
        resolve(error);
      });
    });
    expect(err).toBeDefined();
    expect(err.message).toBe('Format is Authorization: Bearer [token] or Jwt [token]');
  });

  it('should throw if authorization header is not Bearer nor JWT', async () => {
    req.headers = { authorization: 'Basic foobar' };
    const err = await new Promise((resolve) => {
      restifyJWT({ secret: 'shhhh' })(req, res, (error) => {
        resolve(error);
      });
    });
    expect(err).toBeDefined();
    expect(err.body.code).toBe('InvalidCredentials');
  });

  it('should throw if authorization header is not well-formatted jwt', async () => {
    req.headers = { authorization: 'Bearer wrongjwt' };
    const err = await new Promise((resolve) => {
      restifyJWT({ secret: 'shhhh' })(req, res, (error) => {
        resolve(error);
      });
    });
    expect(err).toBeDefined();
    expect(err.body.code).toBe('InvalidCredentials');
  });

  it('should throw if jwt is an invalid json', async () => {
    req.headers = {
      authorization: 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.' +
      'eyJpYXQiOjExNTg0MDcxNjksImp0aSI6ImVhZDU4YTk1LWY1NDUtNDA1My04Y2RhLTA0' +
      'ODdjYWIYgTBmMiIsImV4cCI6MTUxMTExMDc4OX0.foo'
    };
    const err = await new Promise((resolve) => {
      restifyJWT({ secret: 'shhhh' })(req, res, (error) => {
        resolve(error);
      });
    });
    expect(err).toBeDefined();
    expect(err.body.code).toBe('InvalidCredentials');
  });

  it('should throw if authorization header is not valid jwt', async () => {
    const secret = 'shhhhhh';
    const token = jwt.sign({ foo: 'bar' }, secret);
    req.headers = { authorization: 'Bearer ' + token };

    const err = await new Promise((resolve) => {
      restifyJWT({ secret: 'different-shhhh' })(req, res, (error) => {
        resolve(error);
      });
    });
    expect(err).toBeDefined();
    expect(err.body.code).toBe('InvalidCredentials');
    expect(err.jse_cause.message).toBe('invalid signature');
  });

  it('should throw if audience is not expected', async () => {
    const secret = 'shhhhhh';
    const token = jwt.sign({ foo: 'bar', aud: 'expected-audience' }, secret);
    req.headers = { authorization: 'Bearer ' + token };

    const err = await new Promise((resolve) => {
      restifyJWT({ secret: 'shhhhhh', audience: 'not-expected-audience' })(req, res, (error) => {
        resolve(error);
      });
    });
    expect(err).toBeDefined();
    expect(err.body.code).toBe('InvalidCredentials');
    expect(err.jse_cause.message).toBe('jwt audience invalid. expected: not-expected-audience');
  });

  it('should throw if token is expired', async () => {
    const secret = 'shhhhhh';
    const token = jwt.sign({ foo: 'bar', exp: Math.floor(Date.now() / 1000) - 1 }, secret);
    req.headers = { authorization: 'Bearer ' + token };

    const err = await new Promise((resolve) => {
      restifyJWT({ secret: 'shhhhhh' })(req, res, (error) => {
        resolve(error);
      });
    });
    expect(err).toBeDefined();
    expect(err.body.code).toBe('Unauthorized');
    expect(err.message).toBe('The token has expired');
  });

  it('should throw if token issuer is wrong', async () => {
    const secret = 'shhhhhh';
    const token = jwt.sign({ foo: 'bar', iss: 'http://foo' }, secret);
    req.headers = { authorization: 'Bearer ' + token };

    const err = await new Promise((resolve) => {
      restifyJWT({ secret: 'shhhhhh', issuer: 'http://wrong' })(req, res, (error) => {
        resolve(error);
      });
    });
    expect(err).toBeDefined();
    expect(err.body.code).toBe('InvalidCredentials');
    expect(err.jse_cause.message).toBe('jwt issuer invalid. expected: http://wrong');
  });

  it('should use errors thrown from custom getToken function', async () => {
    function getTokenThatThrowsError() {
      throw new errors.InvalidCredentialsError('Invalid token!');
    }

    const err = await new Promise((resolve) => {
      restifyJWT({
        secret: 'shhhhhh',
        getToken: getTokenThatThrowsError,
      })(req, res, (error) => {
        resolve(error);
      });
    });
    expect(err).toBeDefined();
    expect(err.message).toBe('Invalid token!');
  });

  it('should throw error when signature is wrong', async () => {
    const secret = 'shhh';
    const token = jwt.sign({ foo: 'bar', iss: 'http://www' }, secret);
    const newContent = Buffer.from('{foo: \'bar\', edg: \'ar\'}').toString('base64');
    const splitetToken = token.split('.');
    splitetToken[1] = newContent;
    const newToken = splitetToken.join('.');
    
    req.headers = { authorization: 'Bearer ' + newToken };
    
    const err = await new Promise((resolve) => {
      restifyJWT({ secret: secret })(req, res, (error) => {
        resolve(error);
      });
    });

    expect(err).toBeDefined();
    expect(err.body.code).toBe('InvalidCredentials');
    expect(err.jse_cause.message).toBe('invalid token');
  });
});

describe('work tests', () => {
  let req = {};
  const res = {};

  it('should work if authorization header is valid jwt ("Bearer <token>")', async () => {
    const secret = 'shhhhhh';
    const token = jwt.sign({ foo: 'bar' }, secret);
    req.headers = { authorization: 'Bearer ' + token };

    await new Promise((resolve) => {
      restifyJWT({ secret: secret })(req, res, () => {
        expect(req.user.foo).toBe('bar');
        resolve();
      });
    });
  });

  it('should work if authorization header is valid jwt ("JWT <token>")', async () => {
    const secret = 'shhhhhh';
    const token = jwt.sign({ foo: 'bar' }, secret);
    req.headers = { authorization: 'JWT ' + token };

    await new Promise((resolve) => {
      restifyJWT({ secret: secret })(req, res, () => {
        expect(req.user.foo).toBe('bar');
        resolve();
      });
    });
  });

  it('should work if authorization header is valid with a buffer secret', async () => {
    const secret = Buffer.from(
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      'base64',
    );
    const token = jwt.sign({ foo: 'bar' }, secret);
    req.headers = { authorization: 'Bearer ' + token };

    await new Promise((resolve) => {
      restifyJWT({ secret: secret })(req, res, () => {
        expect(req.user.foo).toBe('bar');
        resolve();
      });
    });
  });

  it('should set userProperty if option provided', async () => {
    const secret = 'shhhhhh';
    const token = jwt.sign({ foo: 'bar' }, secret);
    req.headers = { authorization: 'Bearer ' + token };

    await new Promise((resolve) => {
      restifyJWT({ secret: secret, userProperty: 'auth' })(req, res, () => {
        expect(req.auth.foo).toBe('bar');
        resolve();
      });
    });
  });

  it('should work if no authorization header and credentials are not required', async () => {
    req = {};
    const err = await new Promise((resolve) => {
      restifyJWT({ secret: 'shhhh', credentialsRequired: false })(req, res, (error) => {
        resolve(error);
      });
    });
    expect(err).toBeUndefined();
  });

  it('should work if token is expired and credentials are not required', async () => {
    const secret = 'shhhhhh';
    const token = jwt.sign({ foo: 'bar', exp: Math.floor(Date.now() / 1000) - 1 }, secret);
    req.headers = { authorization: 'Bearer ' + token };

    const err = await new Promise((resolve) => {
      restifyJWT({ secret: secret, credentialsRequired: false })(req, res, (error) => {
        resolve(error);
      });
    });
    expect(err).toBeUndefined();
    expect(req.user).toBeUndefined();
  });

  it('should not work if no authorization header', async () => {
    req = {};
    const err = await new Promise((resolve) => {
      restifyJWT({ secret: 'shhhh' })(req, res, (error) => {
        resolve(error);
      });
    });
    expect(err).toBeDefined();
  });

  it('should work with a custom getToken function', async () => {
    const secret = 'shhhhhh';
    const token = jwt.sign({ foo: 'bar' }, secret);
    req.headers = {};
    req.query = { token };

    const getTokenFromQuery = (req) => req.query.token;

    await new Promise((resolve) => {
      restifyJWT({ secret: secret, getToken: getTokenFromQuery })(req, res, () => {
        expect(req.user.foo).toBe('bar');
        resolve();
      });
    });
  });

  it('should work with a secretCallback function that accepts header argument', async () => {
    const secret = 'shhhhhh';
    const secretCallback = (req, headers, payload, cb) => {
      expect(headers.alg).toBe('HS256');
      expect(payload.foo).toBe('bar');
      process.nextTick(() => cb(null, secret));
    };
    const token = jwt.sign({ foo: 'bar' }, secret);
    req.headers = { authorization: 'Bearer ' + token };

    await new Promise((resolve) => {
      restifyJWT({ secret: secretCallback })(req, res, () => {
        expect(req.user.foo).toBe('bar');
        resolve();
      });
    });
  });
});