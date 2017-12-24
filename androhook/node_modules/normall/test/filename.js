var assert = require('assert');

var filename = require('../').filename;


describe('Filename normalization', function() {
    it('should normalize spaces', function() {
        assert.equal(filename('1 2 3'), '1_2_3');
    });

    it('should ignore trailing spaces', function() {
        assert.equal(filename('a b c '), 'a_b_c');
    });

    it('should remove illegal chars', function() {
        assert.equal(filename('abc 38 ./.#$#@!/'), 'abc_38');
    });

    it('should strip dots', function() {
        assert.equal(filename('a.b.c'), 'abc');
    });

    it('should convert to lowecase', function() {
        assert.equal(filename('AbC DeF gHi'), 'abc_def_ghi');
    });

});
