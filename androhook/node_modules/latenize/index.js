var latenize_map = require('./latinize_map');

function latenize(str){
  return str.replace(/[^A-Za-z0-9]/g, function(x) { return latenize_map[x] || x; });
}

latenize.isLatin = function(str){
  return str === latenize(str);
};

module.exports = latenize;
