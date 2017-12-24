# Brightml

Smart utility rendering markdown-ready HTML.

## Install

```Shell
$ npm install brightml
```

## Use

Clean all HTML at once :

```JavaScript
var brightml = require('brightml');

var HTMLString = '<table><tr><td>Title 1</td><td>Title 2</td></tr><tr><td>Data 1</td><td>Data 2</td></tr></table>';

var cleanHTML = brightml.clean(HTMLString);
//  cleanHTML is :
//  <table>
//    <thead>
//      <tr>
//        <th>Title 1</th>
//        <th>Title 2</th>
//      </tr>
//    </thead>
//    <tbody>
//      <tr>
//        <td>Data 1</td>
//        <td>Data 2</td>
//      </tr>
//    </tbody>
//  </table>
```

Or use the module's functions as required :

```JavaScript
var brightml = require('brightml');

var HTMLString = '<table><tr><td>Title 1</td><td>Title 2</td></tr><tr><td>Data 1</td><td>Data 2</td></tr></table>';

brightml.parse(HTMLString);
brightml.formatTables();
var cleanHTML = brightml.render();
//  cleanHTML is :
//  <table>
//    <thead>
//      <tr>
//        <th>Title 1</th>
//        <th>Title 2</th>
//      </tr>
//    </thead>
//    <tbody>
//      <tr>
//        <td>Data 1</td>
//        <td>Data 2</td>
//      </tr>
//    </tbody>
//  </table>
```

## What it does

Using `brightml.clean(html)` performs the following operations in order.

#### brightml.parse(HTMLString)

Convert HTML to DOM using [cheerio](https://github.com/cheeriojs/cheerio).

#### brightml.retrieveFootNotes()

For cross-referenced links, handle retrieving the foot/endnotes before the next `<h1>` tag to keep notes within a chapter section.

The footnotes are then formatted as follow:

```HTML
<h1>Footnotes</h1>
<p>
  See how to properly format a footnote<sup id="footnote-ref"><a href="#footnote">1</a></sup>.
</p>
<!-- Some more content -->
<p>
  <sup id="footnote">
    Footnotes are in a paragraph and a sup tag. Link to go back to reference is at the end of the footnote.
    <a href="#footnote-ref"></a>
  </sup>
</p>
```

#### brightml.setAnchorsId()

Try to set `<a>` tags `id` attribute on their direct parent if possible.

#### brightml.cleanElements()

* Remove empty tags.
* Remove forbidden HTML tags and place their HTML content in a `<p>` instead.
* Remove forbidden HTML attributes.
* Remove unallowed links schema in HTML attributes.

This operation uses the `rules.js` file to determine which tags/attributes/schemes are allowed.

#### brightml.cleanImagesInTitles()

Move `<img>` tags in titles right after the concerned `<h>` tag.

#### brightml.normalizeTitlesId()

Set an `id` attribute on each `<h>` tag. The `id` is based on the title tag content.

Each reference to this `id` will be modified in consequence.

```HTML
<h1 id="some-id">A great title</h1>
<a href="#some-id">Back to a great title</a>
```
will become:
```HTML
<h1 id="a_great_title">A great title</h1>
<a href="#a_great_title">Back to a great title</a>
```

#### brightml.removeNestedTables()

Replace nested `<table>` tags by a warning message followed by their content in a simple `<td>` tag.

#### brightml.formatTables()

Ensure every `<table>` elements look the same.

Used schema :

```HTML
<!-- Move caption before <table> if any -->
<caption></caption>

<table>
  <!-- Ensure the first row contains <th> tags in a <thead> element -->
  <thead>
    <tr>
      <th>Title 1</th>
      <th>Title 2</th>
    </tr>
  </thead>
  <!-- Ensure all remaining rows are inside a <tbody> element -->
  <tbody>
    <tr>
      <td>Row 1 - Data 1</td>
      <td>Row 1 - Data 2</td>
    </tr>
    <tr>
      <td>Row 2 - Data 1</td>
      <td>Row 2 - Data 2</td>
    </tr>
  </tbody>
</table>
```

#### brightml.cleanTableCells()

Ensure every `<th>` and `<td>` tags don't contain a `<p>` tag to prevent line breaking.

#### brightml.render()

Returns the current state of `HTMLString` passed to `brightml.parse(HTMLString)`.