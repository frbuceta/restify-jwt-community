const jwt = require('jsonwebtoken');
const restifyJWT = require('../lib');

describe('string tokens', () => {
  const req = {};
  const res = {};

  it('should work with a valid string token', async () => {
    const secret = 'shhhhhh';
    const token = jwt.sign('foo', secret);

    req.headers = { authorization: `Bearer ${token}` };

    await new Promise((resolve) => {
      restifyJWT({ secret })(req, res, () => {
        expect(req.user).toBe('foo');
        resolve();
      });
    });
  });
});