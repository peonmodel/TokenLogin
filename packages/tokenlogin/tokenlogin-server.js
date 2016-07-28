/*global TwoFactorLogin: true*/

import { Meteor } from 'meteor/meteor';
import { Mongo } from 'meteor/mongo';
import { check, Match } from 'meteor/check';
import { Random } from 'meteor/random';
import { DDPRateLimiter } from 'meteor/ddp-rate-limiter';
import { Accounts } from 'meteor/accounts-base';
import { _ } from 'meteor/underscore';

export { TwoFactorLogin };

let defaultConfig = {
  factors: {
    default: {
      send: (contact, token, factor, settings, callback)=>{
        console.log(`${factor} token: ${token} sent to ${contact} with ${settings}`);
        callback(undefined, 'send success');
      },
      // receive: () => {console.log(`receive function unsupported`);},
      settings: {
        timeout: 5000,  // how long to wait for send server reply before timeout
      },
    },
  },
  generate: ()=>Random.id(6),
  validate: ()=>true,
  settings: null,
  timeout: 1000,
  expiry: 5*(60*1000),  // in milliseconds
  retain: 7*24*60*(60*1000),  // 1 week
  requestInterval: 10*1000,  // 10 seconds
  requestCount: 1,
  profile: 'TokenLogin',
};

/**
 * validateSelector - modifies selector to find user by email or username
 * this function is identical to the selector Meteor Accounts uses
 * this function is not part of the class
 *
 * @param  {string} selector username or email of user
 * @returns {object}          query object for user
 */
function validateSelector(selector){
  if (!_.isString(selector)) {return '';}
  if (selector.indexOf('@') === -1){
    selector = {username: selector};
  } else {
    selector = {'emails.address': selector};
  }
  return selector;
}

/**
 * findUser - find user with password
 *
 * @param  {string} selector username or email of user
 * @param  {string} digest   password hash of user
 * @throws {Meteor.Error} when user with password is not found
 * @returns {object}          user
 */
function findUser(selector, digest){
  let validatedSelector = validateSelector(selector);
  let user = Accounts.users.findOne(validatedSelector);
  if (!user) {
    throw new Meteor.Error(`user/password-not-found`, `The username and password combination is not found`);
  }
  let passwordCheck = Accounts._checkPassword(user, {digest, algorithm: 'sha-256'});
  if (passwordCheck.error) {
    throw new Meteor.Error(`user/password-not-found`, `The username and password combination is not found`);
  }
  return user;
}

class TokenLogin {

  /**
   * constructor - create a TokenLogin instance
   *
   * @param  {string} identifier      a unique identifier for this instance
   * @param  {object} config = {} contains various configuration settings
   */
  constructor(identifier, config) {
    check(identifier, String);
    this.config = defaultConfig;
    this.validateConfig(config);
    this.collectionName = `${this.config.profile}:${identifier}:Collection${Random.id()}`;
    this.collection = new Mongo.Collection(this.collectionName);
    this.collection._ensureIndex({expireAt: 1}, {expireAfterSeconds: 0});
    this.collection._ensureIndex({verifyAt: 1}, {expireAfterSeconds: this.config.retain/1000});

    this.defineMethods(identifier);

    // invalidates normal login
    Accounts.validateLoginAttempt(attempt => {
      let allowed = ['login', 'verifyEmail', 'resetPassword'];
      if (_.contains(allowed, attempt.methodName) && attempt.type === 'resume'){return true;}
      return false;
    });
  }

  /**
   * validateConfig - validates the configuration, replace with defaults otherwise
   *
   * @param  {object} config = {} configuration object
   */
  validateConfig(config = {}){
    _.each(config.factors, (factor, key)=>{
      this.addFactor(factor, key);
    });
    delete config.factors;
    check(config, {
      generate: Match.Maybe(Function),
      validate: Match.Maybe(Function),
      settings: Match.Maybe(Object),
      expiry: Match.Maybe(Match.Integer),
      retain: Match.Maybe(Match.Integer),
      requestInterval: Match.Maybe(Match.Integer),
      requestCount: Match.Maybe(Match.Integer),
      profile: Match.Maybe(String),
    });
    Object.assign(this.config, config);
  }

  /**
   * addFactor - add a factor to TokenLogin instance
   *
   * @param  {string} factor sending method, user-defined function to call to send factor
   * @param  {string} key    name of factor, i.e. 'telegram', 'SMS' or 'email'
   */
  addFactor(factor, key){
    check(key, String);

    check(factor, {
      send: Function,
      // receive: Match.Maybe(Function),
      settings: Match.Maybe(Object),
    });
    // if (!factor.send) {factor.send = defaultConfig.factors.default.send;}
    // if (!factor.receive) {factor.receive = defaultConfig.factors.default.receive;}
    // if (!factor.settings) {factor.settings = defaultConfig.factors.default.settings;}
    // will overwrite existing factors
    this.config.factors[key] = factor;
  }

  /**
   * defineMethods - defines the Meteor methods required by client-side
   * also set the rate limits for the methods
   *
   * @param  {string} identifier unique identifier string, used to name methods
   */
  defineMethods(identifier){
    this.identifier = identifier;
    let prefix = `TokenLogin:${this.identifier}`;
    let instance = this;
    Meteor.methods({

      /**
       * requestToken - allow client-side to request a confirmation token
       *
       * @param {string} selector username or email of user logging in
       * @param {string} digest password hash of user logging in
       * @throws {Meteor.Error} when user is not found or contact details in user profile does not
       * correspond with configuration details of session
       * @returns {string}  session id of confirmation
       */
      [`${prefix}/requestToken`]:function requestToken(selector, digest){
        check(selector, String);
        check(digest, String);
        let user = findUser(selector, digest);
        let notify = get(user, `profile.${instance.config.profile}`);
        check(notify, {contact: String, factor: String});
        let { contact, factor } = notify;
        if (!instance.config.factors[factor]){
          throw new Meteor.Error(`${factor} not supported`);
        }
        instance.invalidateSession(this.connection.id);
        return instance.requestToken(this.connection.id, user, contact, factor);
      },
      /**
       * getLoginToken - get Meteor login service token
       *
       * @param {string} selector username or email of user logging in
       * @param {string} digest password hash of user logging in
       * @throws {Meteor.Error} when user is not found
       * @param  {string} token     token sent to factor
       * @returns {boolean}           true when session is verified
       */
      [`${prefix}/getLoginToken`]:function getLoginToken(selector, digest, token){
        check(selector, String);
        check(digest, String);
        check(token, String);
        let user = findUser(selector, digest);
        if (instance.verifyToken(this.connection.id, user, token)) {
          return instance.saveMeteorServiceToken(user);
        } else {
          // wrong token
          throw new Meteor.Error(`invalid token-session pair`);
        }
      },

      /**
       * invalidateSession - allow client-side to cancel a verification session
       *
       * @returns {number}           1 when session is removed, 0 otherwise
       */
      [`${prefix}/invalidateSession`]:function invalidateSession(){
        return instance.invalidateSession(this.connection.id);
      },
      /**
       * verifyContact - return contact details of active user where token would be sent to
       *
       * @param {string} selector username or email of user logging in
       * @param {string} digest password hash of user logging in
       * @throws {Meteor.Error} when user not found
       * @returns {object}  contact details
       */
      [`${prefix}/verifyContact`]:function verifyContact(selector, digest){
        check(selector, String);
        check(digest, String);
        let user = findUser(selector, digest);
        return instance.verifyContact(user);
      },
      /**
       * assertOpenSession - check if there is a session of id awaiting token
       * useful for checking if need to regenerate token
       *
       * @param {string} selector username or email of user logging in
       * @param {string} digest password hash of user logging in
       * @throws {Meteor.Error} when user not found
       * @returns {boolean }  true if session exist and awaiting token
       */
      [`${prefix}/assertOpenSession`]:function assertOpenSession(selector, digest){
        check(selector, String);
        check(digest, String);
        let user = findUser(selector, digest);
        return instance.assertOpenSession(user, this.connection.id);
      },
    });

    // Set DDP rate limits
    let requestTokenRule = {
      userId: this.config.validate,
      type: 'method',
      name: `${prefix}/requestToken`,
    };
    DDPRateLimiter.addRule(requestTokenRule, this.config.requestCount, this.config.requestInterval);

    let getLoginTokenRule = {
      userId: this.config.validate,
      type: 'method',
      name: `${prefix}/getLoginToken`,
    };
    DDPRateLimiter.addRule(getLoginTokenRule, this.config.requestCount, this.config.requestInterval);

    let invalidateSessionRule = {
      userId: this.config.validate,
      type: 'method',
      name: `${prefix}/invalidateSession`,
    };
    DDPRateLimiter.addRule(invalidateSessionRule, this.config.requestCount, this.config.requestInterval);

    let verifyContactRule = {
      userId: this.config.validate,
      type: 'method',
      name: `${prefix}/verifyContact`,
    };
    DDPRateLimiter.addRule(verifyContactRule, this.config.requestCount, this.config.requestInterval);

    let assertOpenSessionRule = {
      userId: this.config.validate,
      type: 'method',
      name: `${prefix}/assertOpenSession`,
    };
    DDPRateLimiter.addRule(assertOpenSessionRule, this.config.requestCount, this.config.requestInterval);

  }

  /**
   * assertOpenSession - check if there is a session of id awaiting token
   * useful for checking if need to regenerate token
   *
   * @param {object} user Meteor.user()
   * @param {string} connectionId id of session to check
   * @returns {boolean }  true if session exist and awaiting token
   */
  assertOpenSession(user, connectionId){
    let session = this.collection.findOne({connectionId: connectionId, userId: user._id});
    if (!session) {return false;}
    if (!!session.verifyAt) {return false;}  // session is closed
    if ((new Date() - new Date(session.expireAt)) > 0) {return false;}
    return true;
  }

  /**
   * sendToken - sends token via the factor user-defined
   * as the user-defined send function may be asynchronous, so is this
   *
   * @param  {string} contact address to send token to
   * @param  {string} token   token used for verification
   * @param  {string} factor  name of factor to sent token via
   * @param {function} callback function to pass to async send method
   */
  sendToken(contact, token, factor, callback){
    let method = this.config.factors[factor];
    if (!method) {
      console.error(`error, ${factor} not supported`);
      console.log(`printing token on console, ${token}`);
    }

    // timeout condition in case user-defined function does not call callback
    let timeout = get(method, 'settings.timeout') || this.config.timeout;
    Meteor.setTimeout(()=>{
      callback(new Meteor.Error(`sending token to ${contact} via ${factor} timed out`), undefined);
    }, timeout);

    method.send(contact, token, factor, method.settings, (err, res)=>{
      if (err) {
        if (err instanceof Meteor.Error) {callback(err);}
        else {callback(new Meteor.Error(err));}
      }
      else {callback(undefined, res);}
    });
  }

  /**
   * invalidateSession - invalidates a confirmation session that is still open
   *
   * @param  {string} connectionId id of session to invalidate
   * @returns {number}           1 if session is successfully invalidated
   */
  invalidateSession(connectionId){
    return this.collection.remove({connectionId: connectionId, verifyAt: {$exists: false}});
  }

  /**
   * verifyContact - return contact details of active user where token would be sent to
   *
   * @param {object} user Meteor.user
   * @returns {object}  contact details
   */
  verifyContact(user){
    return get(user, `profile.${this.config.profile}`);
  }

  /**
   * requestToken - gets wrapAsync version of requestTokenAsync, behaves synchronously
   *
   * @returns {function}  wrapAsync-ed function
   */
  get requestToken(){
    return Meteor.wrapAsync(this.requestTokenAsync);
  }

  /**
   * requestTokenAsync - request a token to login user, is asynchronous
   *
   * @param {string} connectionId id used for subsequent queries
   * @param  {string} contact essential contact address, i.e. phone number or email address
   * @param  {string} factor  name of factor, i.e. 'telegram', 'SMS' or 'email'
   * @param {function} callback function to pass to async send method
   */
  requestTokenAsync(connectionId, user, contact, factor, callback){
    let token = this.generateToken();
    this.createSession(connectionId, user, token, factor);

    this.sendToken(contact, token, factor, (err/*, res*/)=>{
      if (err) {callback(err);}
      else {callback(undefined, true);}
    });
  }

  /**
     * isVerified - check if session is verified
     *
     * @param  {string} connectionId id of session to check
     * @returns {boolean}           true when session is verified
     */
  isVerified(connectionId){
    let session = this.collection.findOne({connectionId});
    return !!get(session, 'verifyAt');
  }

  /**
   * verifyToken - verify a token - session
   *
   * @param  {object} user Meteor.user()
   * @param  {string} connectionId id of session to verify
   * @param  {string} token     token used to verify session
   * @returns {boolean}           true when session is verified
   */
  verifyToken(user, connectionId, token){
    let session = this.collection.findOne({connectionId: connectionId, userId: user._id});
    if (!session){console.log('no session'); return false;}
    if (!!session.verifyAt){console.log('already verified'); return false;}
    if ((new Date() - new Date(session.expireAt)) > 0) {console.log('expired'); return false;}
    if (session.token !== token) {console.log('wrong token'); return false;}
    this.collection.update(session._id, {
      $set: {verifyAt: new Date()},
      $unset: {expireAt: true},
    });
    return true;
  }

  /**
   * createSession - creates a verification session
   *
   * @param {string} connectionId id used for subsequent queries
   * @param  {object} user Meteor.user()
   * @param  {string} token  unique string for verification
   * @param  {string} factor name of method token should be sent via
   * @returns {string}        id of session created
   */
  createSession(connectionId, user, token, factor){
    return this.collection.insert({
      token,
      factor,
      expireAt: new Date((new Date()).getTime() + this.config.expiry),
      userId: user._id,
      connectionId
    });
  }

  /**
   * generateToken - generates a token, uses user defined function to create unique verification token
   *
   * @returns {string}  unique token string used for verification of session
   */
  generateToken(){
    return this.config.generate();
  }


  /**
   * saveMeteorServiceToken - saves a stampedLoginToken to Meteor user services
   * allows user to login with a OTP token
   *
   * @param  {object} user Meteor.user()
   * @returns {string}      loginToken
   */
  saveMeteorServiceToken(user){
    // this login service token is different from the 2FA token
    let stampedToken = Accounts._generateStampedLoginToken();
    let res = Meteor.users.update(user._id, {$push: {
      'services.resume.loginTokens': Accounts._hashStampedToken(stampedToken),
    }});
    if (!res) {throw new Meteor.Error(`unable to save token to user services`);}
    return stampedToken.token;
  }
}

/**
 * get - helper function to get value in deeply nested objects
 *
 * @param  {object} obj       object to get value from
 * @param  {string|array} ...params combination of strings and arrays to navigate to value
 * @returns {*}           value to get
 */
function get (obj, ...params) {
  function getObject(object, path){
    if (_.isUndefined(object)){return undefined;}
    if (!_.isEmpty(path)){
      let cur = path.shift(1);
      return getObject(object[cur], path);
    }
    return object;
  }

  let path = _.flatten(params)
              .filter(val=>_.isString(val) || _.isNumber(val))
              .map(val=> val.toString().split(/\.|\[|\]|,/g));
  path = _.flatten(path).filter(val=>!!val);
  return getObject(obj, path);
}

TwoFactorLogin = new TokenLogin('LoginSession', {
  factors: {
    telegram: {
      send: (contact, token, factor, settings, callback)=>{
        console.log(`${factor} token: ${token} sent to ${contact} with ${settings}`);
        callback(undefined, 'send success');
      }
    },
    email: {
      send: (contact, token, factor, settings, callback)=>{
        console.log(`${factor} token: ${token} sent to ${contact} with ${settings}`);
        callback(undefined, 'send success');
      }
    },
  },
  generate: ()=>Random.id(6),
  profile: 'TwoFactorLogin',

});
