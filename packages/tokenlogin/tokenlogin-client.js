/*global TwoFactorLogin: true*/

import { Meteor } from 'meteor/meteor';
import { check } from 'meteor/check';
import { Accounts } from 'meteor/accounts-base';

export { TwoFactorLogin };

/**
 * class representing a client-side TokenLogin instance
 */
class TokenLogin {

  /**
   * constructor - create a TokenLogin instance,
   * server-side must have TokenLogin instance initialised with same identifier
   * multiple client-side instance may communicate with the same server-side instance
   *
   * @param  {string} identifier      a unique identifier for this instance
   */
  constructor(identifier, {profile} = {}){
    check(identifier, String);
    this.identifier = identifier;
    this.prefix = `TokenLogin:${this.identifier}`;
    this.config = {profile};
  }

  /**
   * requestToken - request a confirmation token for user action
   *
   * @param  {string} selector username or email of user logging in
   * @param  {string} password password of user logging in
   * @param  {function} callback function to call when server returns result
   */
  requestToken(selector, password, callback){
    check(selector, String);
    check(password, String);
    check(callback, Function);
    let digest = Accounts._hashPassword(password).digest;
    Meteor.call(`${this.prefix}/requestToken`, selector, digest, (err, res)=>{
      if (!err) {Accounts._setLoggingIn(true);}
      callback(err,res);
    });
  }
  /**
   * getLoginToken - get Meteor login service token
   *
   * @param  {string} selector username or email of user logging in
   * @param  {string} password password of user logging in
   * @param  {string} sessionId session id of TokenAffirm session
   * @param  {string} token     token sent to factor
   * @param  {function} callback  function to call when server returns result
   */
  getLoginToken(selector, password, sessionId, token, callback){
    check(selector, String);
    check(password, String);
    check(sessionId, String);
    check(token, String);
    check(callback, Function);
    let digest = Accounts._hashPassword(password).digest;
    Meteor.call(`${this.prefix}/getLoginToken`, selector, digest, sessionId, token, callback);
  }



  /**
   * login - log in directly after getting Meteor service login token
   *
   * @param  {string} selector username or email of user logging in
   * @param  {string} password password of user logging in
   * @param  {string} sessionId session id of TokenAffirm session
   * @param  {string} token     token sent to factor
   * @param  {type} callback = ()=>{}  optional function to call if login returns
   */
  login(selector, password, sessionId, token, callback = ()=>{}){
    check(callback, Function);
    this.getLoginToken(selector, password, sessionId, token, (err, res)=>{
      if (res) {Accounts.loginWithToken(res, (loginErr)=>{
        Accounts._setLoggingIn(false);
        if (loginErr) {callback(loginErr);}
        else {callback(undefined, true);}
      });}
      else {
        // failed to get login token
        Accounts._setLoggingIn(false);
        callback(err);
      }
    });
  }

  /**
   * invalidateSession - invalidates a session, set LoggingIn to be false
   *
   * @param  {string} sessionId id of session to invalidate
   * @param  {function} callback = ()=>{}  optional function to call when server returns result
   */
  invalidateSession(sessionId, callback = ()=>{}){
    check(sessionId, String);
    check(callback, Function);
    Meteor.call(`${this.prefix}/invalidateSession`, sessionId, (err, res)=>{
      Accounts._setLoggingIn(false);
      callback(err, res);
    });
  }

  /**
   * verifyContact - request contact details of active user when token will be sent to
   *
   * @param  {string} selector username or email of user logging in
   * @param  {string} password password of user logging in
   * @param  {function} callback function to call when server returns result
   */
  verifyContact(selector, password, callback){
    check(selector, String);
    check(password, String);
    check(callback, Function);
    let digest = Accounts._hashPassword(password).digest;
    Meteor.call(`${this.prefix}/verifyContact`, selector, digest, callback);
  }

  /**
   * assertOpenSession - check if there is a session of id awaiting token
   * useful for checking if need to regenerate token
   *
   * @param  {string} selector username or email of user logging in
   * @param  {string} password password of user logging in
   * @param  {string} sessionId id of session to check
   * @param  {function} callback = ()=>{}  optional function to call when server returns result
   */
  assertOpenSession(selector, password, sessionId, callback = ()=>{}){
    check(selector, String);
    check(password, String);
    check(sessionId, String);
    check(callback, Function);
    let digest = Accounts._hashPassword(password).digest;
    Meteor.call(`${this.prefix}/assertOpenSession`, selector, digest, sessionId, callback);
  }

}

TwoFactorLogin = new TokenLogin('LoginSession');
