var should = require('should');
var brightml = require('../index.js');

describe('brightml.parse() / brightml.render()', function() {
    it('should render exactly what was given', function() {
        var input = '<table>'+
            '<caption>Data table</caption>'+
            '<thead>'+
                '<tr><th>Title 1</th><th>Title 2</th></tr>'+
            '</thead>'+
            '<tbody>'+
                '<tr><td>Data 1.1</td><td>Data 1.2</td></tr>'+
                '<tr><td>Data 2.1</td><td>Data 2.2</td></tr>'+
            '</tbody>'+
        '</table>';

        var correctOutput = '<table>'+
            '<caption>Data table</caption>'+
            '<thead>'+
                '<tr><th>Title 1</th><th>Title 2</th></tr>'+
            '</thead>'+
            '<tbody>'+
                '<tr><td>Data 1.1</td><td>Data 1.2</td></tr>'+
                '<tr><td>Data 2.1</td><td>Data 2.2</td></tr>'+
            '</tbody>'+
        '</table>';

        brightml.parse(input);
        var output = brightml.render();

        output.should.be.equal(correctOutput);
    });
});

describe('brightml.formatTables()', function() {
    it('should move <caption> before <table>', function() {
        var input = '<table>'+
            '<caption>Data table</caption>'+
            '<thead>'+
                '<tr><th>Title 1</th><th>Title 2</th></tr>'+
            '</thead>'+
            '<tbody>'+
                '<tr><td>Data 1.1</td><td>Data 1.2</td></tr>'+
                '<tr><td>Data 2.1</td><td>Data 2.2</td></tr>'+
            '</tbody>'+
        '</table>';

        var correctOutput = '<caption>Data table</caption>'+
        '<table>'+
            '<thead>'+
                '<tr><th>Title 1</th><th>Title 2</th></tr>'+
            '</thead>'+
            '<tbody>'+
                '<tr><td>Data 1.1</td><td>Data 1.2</td></tr>'+
                '<tr><td>Data 2.1</td><td>Data 2.2</td></tr>'+
            '</tbody>'+
        '</table>';

        brightml.parse(input);
        brightml.formatTables();
        var output = brightml.render();

        output.should.be.equal(correctOutput);
    });

    it('should create <thead> and <tbody>', function() {
        var input = '<table>'+
            '<tr><td>Title 1</td><td>Title 2</td></tr>'+
            '<tr><td>Data 1.1</td><td>Data 1.2</td></tr>'+
            '<tr><td>Data 2.1</td><td>Data 2.2</td></tr>'+
        '</table>';

        var correctOutput = '<table>'+
            '<thead>'+
                '<tr><th>Title 1</th><th>Title 2</th></tr>'+
            '</thead>'+
            '<tbody>'+
                '<tr><td>Data 1.1</td><td>Data 1.2</td></tr>'+
                '<tr><td>Data 2.1</td><td>Data 2.2</td></tr>'+
            '</tbody>'+
        '</table>';

        brightml.parse(input);
        brightml.formatTables();
        var output = brightml.render();

        output.should.be.equal(correctOutput);
    });

    it('should move the first row of <tbody> in a new <thead>', function() {
        var input = '<table>'+
            '<tbody>'+
                '<tr><td>Title 1</td><td>Title 2</td></tr>'+
                '<tr><td>Data 1.1</td><td>Data 1.2</td></tr>'+
                '<tr><td>Data 2.1</td><td>Data 2.2</td></tr>'+
            '</tbody>'+
        '</table>';

        var correctOutput = '<table>'+
            '<thead>'+
                '<tr><th>Title 1</th><th>Title 2</th></tr>'+
            '</thead>'+
            '<tbody>'+
                '<tr><td>Data 1.1</td><td>Data 1.2</td></tr>'+
                '<tr><td>Data 2.1</td><td>Data 2.2</td></tr>'+
            '</tbody>'+
        '</table>';

        brightml.parse(input);
        brightml.formatTables();
        var output = brightml.render();

        output.should.be.equal(correctOutput);
    });
});

describe('brightml.cleanTableCells()', function() {
    it('should remove <p> tags from <th> and <td>', function() {
        var input = '<table>'+
            '<thead>'+
                '<tr><th><p>Title 1</p></th><th><p>Title 2</p></th></tr>'+
            '</thead>'+
            '<tbody>'+
                '<tr><td><p>Data 1.1</p></td><td><p>Data 1.2</p></td></tr>'+
                '<tr><td><p>Data 2.1</p></td><td><p>Data 2.2</p></td></tr>'+
            '</tbody>'+
        '</table>';

        var correctOutput = '<table>'+
            '<thead>'+
                '<tr><th>Title 1</th><th>Title 2</th></tr>'+
            '</thead>'+
            '<tbody>'+
                '<tr><td>Data 1.1</td><td>Data 1.2</td></tr>'+
                '<tr><td>Data 2.1</td><td>Data 2.2</td></tr>'+
            '</tbody>'+
        '</table>';

        brightml.parse(input);
        brightml.cleanTableCells();
        var output = brightml.render();

        output.should.be.equal(correctOutput);
    });
});

describe('brightml.removeNestedTables()', function() {
    it('should remove nested <table> elements', function() {
        var input = '<table>'+
            '<thead>'+
                '<tr><th>Title 1</th><th>Title 2</th></tr>'+
            '</thead>'+
            '<tbody>'+
                '<tr><td>'+
                    '<table><tbody><tr><td>Data 1.1</td><td>Data 1.2</td></tr></tbody></table>'+
                '</td></tr>'+
                '<tr><td>Data 2.1</td><td>Data 2.2</td></tr>'+
            '</tbody>'+
        '</table>';

        var correctOutput = '<table>'+
            '<thead>'+
                '<tr><th>Title 1</th><th>Title 2</th></tr>'+
            '</thead>'+
            '<tbody>'+
                '<tr><td><b>Illegal nested table :</b> Data 1.1Data 1.2</td></tr>'+
                '<tr><td>Data 2.1</td><td>Data 2.2</td></tr>'+
            '</tbody>'+
        '</table>';

        brightml.parse(input);
        brightml.removeNestedTables();
        var output = brightml.render();

        output.should.be.equal(correctOutput);
    });
});

describe('brightml.setAnchorsId()', function() {
    it('should set the empty <a> tag id on its direct parent', function() {
        var input = '<p>'+
            '<a id="my-link"></a>'+
            'Sample text'+
        '</p>';

        var correctOutput = '<p id="my-link">'+
            '<a></a>'+
            'Sample text'+
        '</p>';

        brightml.parse(input);
        brightml.setAnchorsId();
        var output = brightml.render();

        output.should.be.equal(correctOutput);
    });

    it('should not replace the direct parent existing id', function() {
        var input = '<p id="mytext">'+
            '<a id="my-link"></a>'+
            'Sample text'+
        '</p>';

        var correctOutput = '<p id="mytext">'+
            '<a id="my-link"></a>'+
            'Sample text'+
        '</p>';

        brightml.parse(input);
        brightml.setAnchorsId();
        var output = brightml.render();

        output.should.be.equal(correctOutput);
    });
});

describe('brightml.normalizeTitlesId()', function() {
    it('should change the title id', function() {
        var input = '<h1 id="345-is-a-weird-id">'+
            'Complex_title 101&amp;# Others'+
        '</h1>';

        var correctOutput = '<h1 id="complex-title-101-others">'+
            'Complex_title 101&amp;# Others'+
        '</h1>';

        brightml.parse(input);
        brightml.normalizeTitlesId();
        var output = brightml.render();

        output.should.be.equal(correctOutput);
    });

    it('should replace references to title id', function() {
        var input = '<h2 id="another-strange-id">'+
            'A great title'+
        '</h2>'+
        '<a href="#another-strange-id">'+
            'Go back'+
        '</a>';

        var correctOutput = '<h2 id="a-great-title">'+
            'A great title'+
        '</h2>'+
        '<a href="#a-great-title">'+
            'Go back'+
        '</a>';

        brightml.parse(input);
        brightml.normalizeTitlesId();
        var output = brightml.render();

        output.should.be.equal(correctOutput);
    });
});

describe('brightml.retrieveFootnotes()', function() {
    it('should move the referenced <p> tag before the next <h1> tag', function() {
        var input = '<h1>Part 1</h1>'+
        '<p>'+
            'Sample footnote'+
            '<sup id="footnote-1-ref">'+
                '<a href="#footnote-1">1</a>'+
            '</sup>'+
        '</p>'+
        '<p>'+
            'Second footnote'+
            '<sup>'+
                '<a id="footnote-2-ref" href="#footnote-2">2</a>'+
            '</sup>'+
        '</p>'+
        '<h1>Part 2</h1>'+
        '<p>Some content</p>'+
        '<p>'+
            '<sup id="footnote-1">'+
                'This should move '+
                '<a href="#footnote-1-ref">back</a>'+
            '</sup>'+
        '</p>'+
        '<h1>Part 3</h1>'+
        '<ol>'+
            '<li id="footnote-2">'+
                '<sup>'+
                    'This too '+
                    '<a href="#footnote-2-ref">back</a>'+
                '</sup>'+
            '</li>'+
        '</ol>';

        var correctOutput = '<h1>Part 1</h1>'+
        '<p>'+
            'Sample footnote'+
            '<sup id="footnote-1-ref">'+
                '<a href="#footnote-1">1</a>'+
            '</sup>'+
        '</p>'+
        '<p>'+
            'Second footnote'+
            '<sup>'+
                '<a id="footnote-2-ref" href="#footnote-2">2</a>'+
            '</sup>'+
        '</p>'+
        '<p>'+
            '<sup id="footnote-1">'+
                '1 This should move '+
                '<a href="#footnote-1-ref">back</a>'+
            '</sup>'+
        '</p>'+
        '<p>'+
            '<sup id="footnote-2">'+
                '2 This too '+
                '<a href="#footnote-2-ref">back</a>'+
            '</sup>'+
        '</p>'+
        '<h1>Part 2</h1>'+
        '<p>Some content</p>'+
        '<p></p>'+
        '<h1>Part 3</h1>'+
        '<ol>'+
        '</ol>';

        brightml.parse(input);
        brightml.retrieveFootnotes();
        var output = brightml.render();

        output.should.be.equal(correctOutput);
    });
});

describe('brightml.cleanElements()', function() {
    it('should remove empty tags', function() {
        var input = '<p>'+
            'Sample text'+
            '<a href="http://lost.com"></a>'+
            '<img src="./logo.png">'+
        '</p>';

        var correctOutput = '<p>'+
            'Sample text'+
            '<img src="./logo.png">'+
        '</p>';

        brightml.parse(input);
        brightml.cleanElements();
        var output = brightml.render();

        output.should.be.equal(correctOutput);
    });

    it('should remove unallowed tags', function() {
        var input = '<p>'+
            'Sample text'+
            '<memo>This should become a span</memo>'+
        '</p>'+
        '<memo>This should turn into a p</memo>';

        var correctOutput = '<p>'+
            'Sample text'+
            '<span><b>Illegal HTML tag removed : </b>This should become a span</span>'+
        '</p>'+
        '<p><b>Illegal HTML tag removed : </b>This should turn into a p</p>';

        brightml.parse(input);
        brightml.cleanElements();
        var output = brightml.render();

        output.should.be.equal(correctOutput);
    });

    it('should remove unallowed attributes', function() {
        var input = '<h1 id="first-title" title="part-1">'+
            'Part 1'+
        '</h1>';

        var correctOutput = '<h1 id="first-title">'+
            'Part 1'+
        '</h1>';

        brightml.parse(input);
        brightml.cleanElements();
        var output = brightml.render();

        output.should.be.equal(correctOutput);
    });

    it('should remove unallowed links schemes', function() {
        var input = '<a href="https://github.com/me/my-git-repo.git">'+
            'Authorized link to my secret git repo'+
        '</a>'+
        '<a href="git://my-git-repo.git">'+
            'Unallowed link to my secret git repo'+
        '</a>';

        var correctOutput = '<a href="https://github.com/me/my-git-repo.git">'+
            'Authorized link to my secret git repo'+
        '</a>'+
        '<a>'+
            'Unallowed link to my secret git repo'+
        '</a>';

        brightml.parse(input);
        brightml.cleanElements();
        var output = brightml.render();

        output.should.be.equal(correctOutput);
    });
});

describe('brightml.clean()', function() {
    it('should do all this at once', function() {
        var input = '<h1 id="first-title" title="part-1">Part 1</h1>'+
        '<p>'+
            'Sample footnote'+
            '<sup id="footnote-1-ref">'+
                '<a href="#footnote-1">1</a>'+
            '</sup>'+
            '<a href="http://lost.com"></a>'+
            '<img src="./logo.png">'+
        '</p>'+
        '<p>'+
            '<memo>This should become a span</memo> '+
            'Second footnote'+
            '<sup>'+
                '<a id="footnote-2-ref" href="#footnote-2">2</a>'+
            '</sup>'+
        '</p>'+
        '<h1>Part 2</h1>'+
        '<p>Some content</p>'+
        '<p>'+
            '<sup id="footnote-1">'+
                'This should move '+
                '<a href="#footnote-1-ref">back</a>'+
            '</sup>'+
        '</p>'+
        '<h1>Part 3</h1>'+
        '<ol>'+
            '<li id="footnote-2">'+
                '<sup>'+
                    'This too '+
                    '<a href="#footnote-2-ref">back</a>'+
                '</sup>'+
            '</li>'+
        '</ol>'+
        '<table>'+
            '<caption>Data table</caption>'+
            '<tr><td>Title 1</td><td>Title 2</td></tr>'+
            '<tr><td>'+
                    '<table><tbody><tr><td>Data 1.1</td><td>Data 1.2</td></tr></tbody></table>'+
            '</td></tr>'+
            '<tr><td><p>Data 2.1</p></td><td><p>Data 2.2</p></td></tr>'+
        '</table>';

        var correctOutput = '<h1 id="part-1">Part 1</h1>'+
        '<p>'+
            'Sample footnote'+
            '<sup id="footnote-1-ref">'+
                '<a href="#footnote-1">1</a>'+
            '</sup>'+
            '<img src="./logo.png">'+
        '</p>'+
        '<p>'+
            '<span><b>Illegal HTML tag removed : </b>This should become a span</span> '+
            'Second footnote'+
            '<sup id="footnote-2-ref">'+
                '<a href="#footnote-2">2</a>'+
            '</sup>'+
        '</p>'+
        '<p>'+
            '<sup id="footnote-1">'+
                '1 This should move '+
                '<a href="#footnote-1-ref">back</a>'+
            '</sup>'+
        '</p>'+
        '<p>'+
            '<sup id="footnote-2">'+
                '2 This too '+
                '<a href="#footnote-2-ref">back</a>'+
            '</sup>'+
        '</p>'+
        '<h1 id="part-2">Part 2</h1>'+
        '<p>Some content</p>'+
        '<h1 id="part-3">Part 3</h1>'+
        '<caption>Data table</caption>'+
        '<table>'+
            '<thead>'+
                '<tr><th>Title 1</th><th>Title 2</th></tr>'+
            '</thead>'+
            '<tbody>'+
                '<tr><td><b>Illegal nested table :</b> Data 1.1Data 1.2</td></tr>'+
                '<tr><td>Data 2.1</td><td>Data 2.2</td></tr>'+
            '</tbody>'+
        '</table>';

        var output = brightml.clean(input);
        output.should.be.equal(correctOutput);
    });
});