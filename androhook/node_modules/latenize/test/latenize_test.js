var latenize = require('../index.js');

/*
  ======== A Handy Little Nodeunit Reference ========
  https://github.com/caolan/nodeunit

  Test methods:
    test.expect(numAssertions)
    test.done()
  Test assertions:
    test.ok(value, [message])
    test.equal(actual, expected, [message])
    test.notEqual(actual, expected, [message])
    test.deepEqual(actual, expected, [message])
    test.notDeepEqual(actual, expected, [message])
    test.strictEqual(actual, expected, [message])
    test.notStrictEqual(actual, expected, [message])
    test.throws(block, [error], [message])
    test.doesNotThrow(block, [error], [message])
    test.ifError(value)
*/

exports['Latenize'] = {
  setUp: function(done) {
    // setup here
    done();
  },
  'latenize': function(t) {
    t.expect(6);
    t.equal(latenize("Piqué"), "Pique");
    t.equal(latenize("Артём Риженков"), "Artyom Rizhenkov");
    t.equal(latenize("Solución"), "Solucion");
    t.equal(latenize.isLatin("Piqué"), false);
    t.equal(latenize.isLatin("Pique"), true);
    t.equal(latenize.isLatin(latenize("Piqué")), true);
    t.done();
  }
};
