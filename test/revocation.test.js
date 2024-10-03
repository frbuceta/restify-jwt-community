const jwt = require('jsonwebtoken');
const restifyJWT = require('../lib');

describe('revoked jwts', () => {
  const secret = 'shhhhhh';
  const revokedId = '1234';

  const middleware = restifyJWT({
    secret: secret,
    isRevoked: (req, payload, done) => {
      done(null, payload.jti && payload.jti === revokedId);
    },
  });

  it('should throw if token is revoked', async () => {
    const req = {};
    const res = {};
    const token = jwt.sign({ jti: revokedId, foo: 'bar' }, secret);

    req.headers = { authorization: `Bearer ${token}` };

    await new Promise((resolve) => {
      middleware(req, res, (err) => {
        expect(err).toBeDefined();
        expect(err.body.code).toBe('Unauthorized');
        expect(err.message).toBe('The token has been revoked.');
        resolve();
      });
    });
  });

  it('should work if token is not revoked', async () => {
    const req = {};
    const res = {};
    const token = jwt.sign({ jti: '1233', foo: 'bar' }, secret);

    req.headers = { authorization: `Bearer ${token}` };

    await new Promise((resolve) => {
      middleware(req, res, () => {
        expect(req.user.foo).toBe('bar');
        resolve();
      });
    });
  });

  it('should throw if error occurs checking if token is revoked', async () => {
    const req = {};
    const res = {};
    const token = jwt.sign({ jti: revokedId, foo: 'bar' }, secret);

    req.headers = { authorization: `Bearer ${token}` };

    await new Promise((resolve) => {
      restifyJWT({
        secret: secret,
        isRevoked: (req, payload, done) => {
          done(new Error('An error occurred'));
        },
      })(req, res, (err) => {
        expect(err).toBeDefined();
        expect(err.message).toBe('An error occurred');
        resolve();
      });
    });
  });
});