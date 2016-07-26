/* global _TwoFactorLogin: true */

import { Meteor } from 'meteor/meteor';
import { Accounts } from 'meteor/accounts-base';

import { TwoFactorLogin } from 'meteor/freelancecourtyard:tokenlogin';

if (Meteor.isDevelopment) {
  _TwoFactorLogin = TwoFactorLogin;
}

Meteor.startup(() => {
  // code to run on server at startup
  if (!Accounts.users.findOne({username: 'u1'})){
    Accounts.createUser({
      username: 'u1',
      password: 'pw',
      profile: {
        TwoFactorLogin: {
          factor: 'telegram',
          contact: 'telegramcontact',
        },
      },
    });
  }
});
