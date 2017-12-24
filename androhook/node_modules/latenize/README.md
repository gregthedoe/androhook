# Latenize [![Gittip](http://badgr.co/gittip/fgribreau.png)](https://www.gittip.com/fgribreau/)

NPM/NodeJS port of Semplice latenize

## Getting Started
Install the module with: `npm install latenize`

```javascript
var latenize = require('latenize');
latinize("Piqué") // => "Pique"
latinize("Solución") // => "Solution"
latinize.isLatin("Piqué")  // => false
latinize.isLatin("Pique")  // => true
latinize.isLatin(latinize("Piqué"))  // => true
```

## Contributing
In lieu of a formal styleguide, take care to maintain the existing coding style. Add unit tests for any new or changed functionality. Lint and test your code using [grunt](https://github.com/cowboy/grunt).

## Donate
[Donate Bitcoins](https://coinbase.com/checkouts/fc3041b9d8116e0b98e7d243c4727a30)

## License
[Semplice](http://semplicewebsites.com/removing-accents-javascript)
Copyright (c) 2013 Francois-Guillaume Ribreau
Licensed under the MIT license.
