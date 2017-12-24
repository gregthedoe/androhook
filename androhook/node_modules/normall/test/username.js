var assert = require('assert');

var username = require('../').username;


describe('Username normalization', function() {
    it('should handle these cases', function() {
        assert.equal(username("Aaron O'Mullan"), 'aaronomullan');
        assert.equal(username("haihan yu"), 'haihanyu');
        assert.equal(username("姓名"), 'xingming');
    });
});
