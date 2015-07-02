/**                                                                                                                                                                                                                                          
 * Module dependencies.                                                                                                                                                                                                                      
 */
var utils = require('../utils')
  , TokenError = require('../errors/tokenerror');


/**                                                                                                                                                                                                                                          
 * Exchanges a device code for an access token. 
                                                                                                                                                                                                                            
 * Callbacks:                                                                                                                                                                                                                                
 *                                                                                                                                                                                                                                           
 * This middleware requires an `issue` callback, for which the function                                                                                                                                                                      
 * signature is as follows:                                                                                                                                                                                                                  
 *                                                                                                                                                                                                                                           
 *     function(client, code, scope, done) { ... }                                                                                                                                                                             
 *                                                                                                                                                                                                                                           
 * `client` is the authenticated client instance attempting to obtain an access                                                                                                                                                              
 * token.  `code` is the device code provided by the device.                                                                                                                                                                   
 * `scope` is the scope of access requested by the client.  `done` is called to                                                                                                                                                              
 * issue an access token:                                                                                                                                                                                                                    
 *                                                                                                                                                                                                                                           
 *     done(err, accessToken, refreshToken, params)                                                                                                                                                                                          
 *                                                                                                                                                                                                                                           
 * `accessToken` is the access token that will be sent to the client.  An                                                                                                                                                                    
 * optional `refreshToken` will be sent to the client, if the server chooses to                                                                                                                                                              
 * implement support for this functionality.  Any additional `params` will be                                                                                                                                                                
 * included in the response.  If an error occurs, `done` should be invoked with                                                                                                                                                              
 * `err` set in idomatic Node.js fashion.                                                                                                                                                                                                    
 *                                                                                                                                                                                                                                           
 * Options:                                                                                                                                                                                                                                  
 *                                                                                                                                                                                                                                           
 *     userProperty    property of `req` which contains the authenticated client (default: 'user')                                                                                                                                           
 *     scopeSeparator  separator used to demarcate scope values (default: ' ')                                                                                                                                                               
 *                                                                                                                                                                                                                                           
 * Examples:                                                                                                                                                                                                                                 
 *                                                                                                                                                                                                                                           
 *     server.exchange(oauth2orize.exchange.deviceCode(function(client, code, scope, done) {                                                                                                                                     
 *       // Validate parameters and generate tokens                                                                                                                                                                                                                               
 *     }));                                                                                                                                                                                                                                  
 *
 * @param {Object} options                                                                                                                                                                                                                   
 * @param {Function} issue                                                                                                                                                                                                                   
 * @return {Function}                                                                                                                                                                                                                        
 * @api public                                                                                                                                                                                                                               
 */
module.exports = function (options, issue) {
  if (typeof options == 'function') {
    issue = options;
    options = undefined;
  }
  options = options || {};

  if (!issue) { throw new TypeError('oauth2orize.deviceCode exchange requires an issue callback'); }

  var userProperty = options.userProperty || 'user';

  // For maximum flexibility, multiple scope spearators can optionally be
  // allowed.  This allows the server to accept clients that separate scope
  // with either space or comma (' ', ',').  This violates the specification,
  // but achieves compatibility with existing client libraries that are already
  // deployed.
  var separators = options.scopeSeparator || ' ';
  if (!Array.isArray(separators)) {
    separators = [ separators ];
  }

  return function device(req, res, next) {
    if (!req.body) { return next(new Error('OAuth2orize requires body parsing. Did you forget app.use(express.bodyParser())?')); }
    
    // The 'user' property of `req` holds the authenticated user.  In the case
    // of the token endpoint, the property will contain the OAuth 2.0 client.
    var client = req[userProperty]
      , code = req.body.code
      , scope = req.body.scope;
      
    if (!code) { return next(new TokenError('Missing required parameter: code', 'invalid_request')); }
    
    if (scope) {
      for (var i = 0, len = separators.length; i < len; i++) {
        var separated = scope.split(separators[i]);
        // only separate on the first matching separator.  this allows for a sort
        // of separator "priority" (ie, favor spaces then fallback to commas)
        if (separated.length > 1) {
          scope = separated;
          break;
        }
      }
      if (!Array.isArray(scope)) { scope = [ scope ]; }
    }
    
    function issued (err, accessToken, refreshToken, params) {
      if (err) {
        if (err.message === '404') { return next(new TokenError('Invalid device code', 'invalid_grant')); }
        if (err.message === '401') { return next(new TokenError('The authorization has not yet been completed', 'authorization_pending')); }
        if (err.message === '403') { return next(new TokenError('The authorization has been declined', 'authorization_rejected')); }
        return next(err);
      }
      if (!accessToken) { return next(new TokenError('Invalid device code', 'invalid_grant')); }
      if (refreshToken && typeof refreshToken == 'object') {
        params = refreshToken;
        refreshToken = null;
      }
      
      var tok = {};
      tok.access_token = accessToken;
      if (refreshToken) { tok.refresh_token = refreshToken; }
      if (params) { utils.merge(tok, params); }
      tok.token_type = tok.token_type || 'Bearer';
      
      var json = JSON.stringify(tok);
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('Pragma', 'no-cache');
      res.end(json);
    }
    
    try {
      var arity = issue.length;
      if (arity == 4) {
        issue(client, code, scope, issued);
      } else {
        issue(client, code, issued);
      }
    } catch (ex) {
      return next(ex);
    }
  };
};