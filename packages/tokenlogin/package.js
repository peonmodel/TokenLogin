Package.describe({
  name: 'freelancecourtyard:tokenlogin',
  version: '0.0.1',
  // Brief, one-line summary of the package.
  summary: '',
  // URL to the Git repository containing the source code for this package.
  git: '',
  // By default, Meteor will default to using README.md for documentation.
  // To avoid submitting documentation, set this field to null.
  documentation: 'README.md'
});

Package.onUse(function(api) {
  api.versionsFrom('1.3.5.1');
  api.use([
    'ecmascript',
    'mongo',
    'check',
    'random',
    'ddp-rate-limiter',
    'accounts-password',
  ]);
  api.imply([
    'accounts-password',
  ]);
  api.mainModule('tokenlogin-server.js', 'server');
  api.mainModule('tokenlogin-client.js', 'client');
});

Package.onTest(function(api) {
  api.use('ecmascript');
  api.use('tinytest');
  api.use('freelancecourtyard:tokenlogin');
  api.mainModule('tokenlogin-tests.js');
});
