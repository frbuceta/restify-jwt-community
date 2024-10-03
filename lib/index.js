'use strict';

/**
 * JWT authentication middleware.
 * @author Francisco Buceta
 */

const async = require('async');
const errors = require('restify-errors');
const jwt = require('jsonwebtoken');
const { unless } = require('express-unless');

const DEFAULT_REVOKED_FUNCTION = (_, __, cb) => cb(null, false);

const isFunction = (object) => typeof object === 'function';

const wrapStaticSecretInCallback = (secret) => (_, __, cb) => cb(null, secret);

module.exports = (options) => {
  if (!options || !options.secret) {
    throw new Error('secret should be set');
  }

  const secretCallback = isFunction(options.secret)
    ? options.secret
    : wrapStaticSecretInCallback(options.secret);

  const isRevokedCallback = options.isRevoked || DEFAULT_REVOKED_FUNCTION;
  const requestProperty = options.userProperty || options.requestProperty || 'user';
  const credentialsRequired = options.credentialsRequired !== false;

  const middleware = (req, res, next) => {
    let token;

    // Handle CORS preflight requests
    if (req.method === 'OPTIONS' && req.headers['access-control-request-headers']) {
      const hasAuthInAccessControl = req.headers['access-control-request-headers']
        .split(',')
        .map(header => header.trim())
        .includes('authorization');

      if (hasAuthInAccessControl) return next();
    }

    // Get the token from the request
    try {
      token = options.getToken ? options.getToken(req) : extractToken(req);
    } catch (e) {
      return next(e);
    }

    // Check if token is required
    if (!token) {
      if (credentialsRequired) {
        return next(new errors.InvalidCredentialsError('No authorization token was found'));
      }
      return next();
    }

    let decodedToken;
    try {
      decodedToken = jwt.decode(token, { complete: true }) || {};
    } catch {
      return next(new errors.InvalidCredentialsError('The token is corrupted'));
    }

    async.parallel([
      (callback) => getSecret(secretCallback, req, decodedToken, callback),
      (callback) => checkRevoked(isRevokedCallback, req, decodedToken, callback),
    ], (err, [secret, revoked]) => {
      if (err) return next(err);
      
      if (revoked) {
        return next(new errors.UnauthorizedError('The token has been revoked.'));
      }

      // Verify the token
      jwt.verify(token, secret, options, (err, decoded) => {
        if (err && credentialsRequired) {
          return next(err.name === 'TokenExpiredError'
            ? new errors.UnauthorizedError('The token has expired')
            : new errors.InvalidCredentialsError(err));
        }
        req[requestProperty] = decoded;
        next();
      });
    });
  };

  const extractToken = (req) => {
    const authHeader = req.headers?.authorization;
    if (!authHeader) return null;

    const parts = authHeader.split(' ');
    if (parts.length === 2 && /^(Bearer|JWT)$/i.test(parts[0])) {
      return parts[1];
    }

    throw new errors.InvalidCredentialsError('Format is Authorization: Bearer [token] or Jwt [token]');
  };

  const getSecret = (callback, req, token, done) => {
    const arity = callback.length;
    return arity === 4
      ? callback(req, token.header, token.payload, done)
      : callback(req, token.payload, done);
  };

  const checkRevoked = (callback, req, token, done) => callback(req, token.payload, done);

  middleware.unless = unless;
  return middleware;
};