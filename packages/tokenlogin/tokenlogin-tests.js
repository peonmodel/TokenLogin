// Import Tinytest from the tinytest Meteor package.
import { Tinytest } from "meteor/tinytest";

// Import and rename a variable exported by tokenlogin.js.
import { name as packageName } from "meteor/freelancecourtyard:tokenlogin";

// Write your tests here!
// Here is an example.
Tinytest.add('tokenlogin - example', function (test) {
  test.equal(packageName, "tokenlogin");
});
