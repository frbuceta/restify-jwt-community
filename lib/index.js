'use strict';

/**
 * JWT authentication middleware.
 * @author Francisco Buceta
 */

const async = require('async');
const errors = require('restify-errors');
const jwt = require('jsonwebtoken');
const unless = require('express-unless');

const DEFAULT_REVOKED_FUNCTION = (_, __, cb) => {
  return cb(null, false);
};

/**
 * @param {any} object
 * @return {boolean}
 */
function isFunction(object) {
  return Object.prototype.toString.call(object) === '[object Function]';
}

/**
 * @param {string} secret
 * @return {function(*, *, *): *}
 */
function wrapStaticSecretInCallback(secret) {
  return (_, __, cb) => {
    return cb(null, secret);
  };
}

module.exports = (options) => {
  if (!options || !options.secret) throw new Error('secret should be set');

  let secretCallback = options.secret;

  if (!isFunction(secretCallback)) {
    secretCallback = wrapStaticSecretInCallback(secretCallback);
  }

  const isRevokedCallback = options.isRevoked || DEFAULT_REVOKED_FUNCTION;

  const _requestProperty = options.userProperty ||
    options.requestProperty ||
    'user';

  // eslint-disable-next-line max-len
  const credentialsRequired = typeof options.credentialsRequired === 'undefined' ?
    true :
    options.credentialsRequired;

  const middleware = (req, res, next) => {
    let token;

    if (
      req.method === 'OPTIONS' &&
      req.headers.hasOwnProperty('access-control-request-headers')
    ) {
      const hasAuthInAccessControl = !!~req.headers[
        'access-control-request-headers'
      ]
        .split(',')
        .map((header) => {
          return header.trim();
        })
        .indexOf('authorization');

      if (hasAuthInAccessControl) {
        return next();
      }
    }

    if (options.getToken && typeof options.getToken === 'function') {
      try {
        token = options.getToken(req);
      } catch (e) {
        return next(e);
      }
    } else if (req.headers && req.headers.authorization) {
      const parts = req.headers.authorization.split(' ');
      if (parts.length === 2) {
        const scheme = parts[0];
        const credentials = parts[1];

        if (/^(?:Bearer|JWT)$/i.test(scheme)) {
          token = credentials;
        } else {
          return next(
            new errors.InvalidCredentialsError(
              'Format is Authorization: Bearer [token] or Jwt [token]',
            ),
          );
        }
      } else {
        return next(
          new errors.InvalidCredentialsError(
            'Format is Authorization: Bearer [token] or Jwt [token]',
          ),
        );
      }
    }

    if (!token) {
      if (credentialsRequired) {
        return next(
          new errors.InvalidCredentialsError(
            'No authorization token was found',
          ),
        );
      } else {
        return next();
      }
    }

    let dToken;

    try {
      dToken = jwt.decode(token, {complete: true}) || {};
    } catch (e) {
      return next(new errors.InvalidCredentialsError('The token is corrupted'));
    }

    async.parallel([
      (callback) => { // getSecret
        const arity = secretCallback.length;
        if (arity === 4) {
          secretCallback(req, dToken.header, dToken.payload, callback);
        } else { // arity == 3
          secretCallback(req, dToken.payload, callback);
        }
      },
      (callback) => { // checkRevoked
        isRevokedCallback(req, dToken.payload, callback);
      },
    ], (err, results) => {
      if (err) {
        return next(err);
      }
      const revoked = results[1];
      if (revoked) {
        return next(
          new errors.UnauthorizedError(
            'The token has been revoked.',
          ),
        );
      }

      const secret = results[0];

      jwt.verify(token, secret, options, (err, decoded) => {
        if (err && credentialsRequired) {
          return (err.name === 'TokenExpiredError') ?
            next(new errors.UnauthorizedError('The token has expired')) :
            next(new errors.InvalidCredentialsError(err));
        }
        req[_requestProperty] = decoded;
        next();
      });
    });
  };

  middleware.unless = unless;
  return middleware;
};
