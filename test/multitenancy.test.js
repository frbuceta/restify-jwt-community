const errors = require('restify-errors');
const jwt = require('jsonwebtoken');
const restifyJWT = require('../lib');

describe('multitenancy', () => {
  const req = {};
  const res = {};

  const tenants = {
    a: {
      secret: 'secret-a',
    },
  };

  const secretCallback = (req, payload, cb) => {
    const issuer = payload.iss;
    if (tenants[issuer]) {
      return cb(null, tenants[issuer].secret);
    }

    return cb(new errors.UnauthorizedError('Could not find secret for issuer.'));
  };

  const middleware = restifyJWT({
    secret: secretCallback,
  });

  it('should retrieve secret using callback', async () => {
    const token = jwt.sign({ iss: 'a', foo: 'bar' }, tenants.a.secret);
    req.headers = { authorization: `Bearer ${token}` };

    await new Promise((resolve) => {
      middleware(req, res, () => {
        expect(req.user.foo).toBe('bar');
        resolve();
      });
    });
  });

  it('should throw if an error occurred when retrieving the token', async () => {
    const token = jwt.sign({ iss: 'inexistent', foo: 'bar' }, 'shhhhhh');
    req.headers = { authorization: `Bearer ${token}` };

    await new Promise((resolve) => {
      middleware(req, res, (err) => {
        expect(err).toBeDefined();
        expect(err.body.code).toBe('Unauthorized');
        expect(err.message).toBe('Could not find secret for issuer.');
        resolve();
      });
    });
  });

  it('should fail if token is revoked', async () => {
    const token = jwt.sign({ iss: 'a', foo: 'bar' }, tenants.a.secret);
    req.headers = { authorization: `Bearer ${token}` };

    await new Promise((resolve) => {
      restifyJWT({
        secret: secretCallback,
        isRevoked: (req, payload, done) => {
          done(null, true);
        },
      })(req, res, (err) => {
        expect(err).toBeDefined();
        expect(err.body.code).toBe('Unauthorized');
        expect(err.message).toBe('The token has been revoked.');
        resolve();
      });
    });
  });
});