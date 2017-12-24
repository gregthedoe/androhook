var fs = require('fs');

var _ = require('lodash');
var cheerio = require('cheerio');

var rules = require('./rules');

// Main DOM object
var $;

// Replace illegal markdown nested tables by a warning
function removeNestedTables() {
    var message = '<b>Illegal nested table :</b>';
    // Check for nested tables
    $('table').has('table').each(function() {
        // Replace nested tables by a warning message
        $(this).find('table').each(function() {
            var $replacement = $('<td>'+message+' '+$(this).text()+'</td>');
            $(this).parent().replaceWith($replacement);
        });
    });
};

// Ensure a common format for tables
// Move <caption> if any before <table>
// Ensure there is a <thead> containing one <tr> with <th> elements
// The rest is in <tbody> in <td> elements
function formatTables() {
    $('table').each(function() {
        $table = $(this);
        // If <table> has children
        if (!!$(this).children().length) {
            // Move <caption> if any
            $caption = $table.find('caption');
            if (!!$caption.length) {
                $caption.insertBefore($table);
            }

            // Remove <colgroup> tags
            $colgroup = $table.find('colgroup');
            if (!!$colgroup.length) {
                $colgroup.remove();
            }

            // Get children
            $children = $table.children();
            // Get first child type
            var firstChildType = getTagName($children);

            switch (firstChildType) {
                // Case <tr>, move the first in a new <thead> and the others in a new <tbody>
                case 'tr':
                    // Encapsulate first <tr> in a new <thead>
                    $thead = $('<thead></thead>');
                    $children.first().wrap($thead);

                    // Encapsulate others in a new <tbody>
                    $tbody = $('<tbody></tbody>');
                    $tbody.append($children.slice(1));
                    $tbody.insertAfter($thead);
                    break;

                // Case <tbody>, move the first <tr> in new <thead>
                case 'tbody':
                    // Create <thead>
                    $thead = $('<thead></thead>');
                    // Capture <tbody>
                    $tbody = $(this).find('tbody');

                    // Encapsulate the first <tr> in a <thead>
                    $tbody.children().first().wrap($thead);
                    // Move <thead> before <tbody>
                    $tbody.children().first().insertBefore($tbody);
                    break;
            }
        }
    });

    // Ensure each <thead> cells are <th>
    $('thead').has('td').each(function() {
        // Replace each <td> by a <th>
        $(this).find('td').each(function() {
            var $th = $('<th></th>');
            $th.html($(this).html());
            $(this).replaceWith($th);
        });
    });
};

// Remove <p> from <th>/<td> table cells
function cleanTableCells() {
    $('td, th').has('p').each(function() {
        // Get paragraph content
        var content = $(this).find('p').html();
        // Replace cell content
        $(this).html(content);
    });
};

// Remove empty or forbidden tags
// Clean up attributes
function cleanElements() {
    // Iterate over elements
    $('*').each(function() {
        var tagName = getTagName($(this));

        // Remove empty tags
        if (!$(this).html().trim()) {
            if (!_.includes(rules.allowedEmpty, tagName)) {
                return $(this).remove();
            }
        }

        // Remove forbidden HTML tags
        if (!rules.allowed[tagName]) {
            // Set content in a <p> tag or in a <span> if parent is a <p>
            var warning = '<b>Illegal HTML tag removed : </b>'+$(this).html();

            var $container = $('<p></p>');
            var $parent = $(this).parent();
            var parentTag;

            if (!!$parent.length) parentTag = getTagName($parent);
            if (parentTag === 'p') $container = $('<span></span>');
            $container.html(warning);

            $(this).replaceWith($container);
            return;
        }

        // Remove forbidden attributes
        var attributes = getTagAttributes($(this));
        for (var key in attributes) {
            if (!_.includes(rules.allowedAttributes, key) && !_.includes(rules.allowed[tagName], key)) {
                delete attributes[key];
                continue;
            }
            // Filter schemes
            if (_.includes(rules.schemaAttributes, key)) {
                var link = attributes[key];
                var allowedLink = rules.allowedSchemes.some(function(scheme) {
                    return _.startsWith(link, scheme);
                });
                if (!allowedLink) {
                    delete attributes[key];
                    continue;
                }
            }

            // Replace line-breaks in attributes
            attributes[key] = attributes[key].replace(/[\n\r\t\v]/g, ' ').trim();
        }
    });
};

// Normalize titles id based on title text
function normalizeTitlesId() {
    var titles = ['h1', 'h2', 'h3', 'h4', 'h5', 'h6'];
    var ids = [];
    var counter;

    titles.forEach(function(title) {
        $(title).each(function() {
            // Compute new id
            var oldId = $(this).attr('id');
            var textId = normalizeId($(this).text());

            var newId = textId;
            counter = 0;
            while (_.includes(ids, newId)) {
                newId = textId+'-'+counter;
                counter++;
            }
            // Prevent obtaining the same id twice
            ids.push(newId);

            // Replace id in href links
            $('*[href="#'+oldId+'"]').each(function() {
                $(this).attr('href', '#'+newId);
            });
            // Replace title id
            $(this).attr('id', newId);
        });
    });
};

// Move <img> tags in titles
function cleanImagesInTitles() {
    var titles = ['h1', 'h2', 'h3', 'h4', 'h5', 'h6'];

    titles.forEach(function(title) {
        $(title).each(function() {
            $img = $(this).children('img');
            $img.insertAfter($(this));
        });
    });
}

// Normalize an id
function normalizeId(id) {
    // Replace any non alpha-numeric character by an hyphen
    id = id.replace(/[^a-zA-Z\d]+/g, '-');
    // Make lowercase
    id = id.toLowerCase();
    return id;
};

// For empty <a> tags with an id attribute, set id on parent
function setAnchorsId() {
    $('a').each(function() {
        var attributes = getTagAttributes($(this));
        if (!!attributes.id) {
            var $parent = $(this).parent();
            if (!$parent.length) return;

            var parentAttributes = getTagAttributes($(this).parent());
            if (!parentAttributes.id) {
                parentAttributes.id = attributes.id;
                delete attributes.id;
            }
        }
    });
};

// Move footnotes before next <h1>
function retrieveFootnotes() {
    $('a').each(function() {
        // Get origin id and href attributes
        var attributes = getTagAttributes($(this));
        var originHref = attributes.href;
        var originId = attributes.id;

        // originId could also be set on parent <sup> tag
        if (!originId) {
            var $parent = $(this).parent();
            if (!$parent.length) return;

            var parentTag = getTagName($parent);
            if (parentTag !== 'sup') return;

            var parentAttributes = getTagAttributes($parent);
            originId = parentAttributes.id;
        }

        // Both id and href must be set in a footnote origin link
        if (!originHref || !originId) return;

        // Check if href is an id-like link
        if (_.startsWith(originHref, '#')) {
            // Get referenced element
            var $referencedTag = $(originHref);
            if (!$referencedTag.length) return;

            // Check that referred element has a link back to origin
            var $linkToOrigin = $('a[id="'+originId+'"]');
            if (!$referencedTag.has($linkToOrigin)) return;

            // Find next <h1> tag
            var $nextH1 = getNextH1($(this));
            if (_.isNull($nextH1)) return;

            // Change referred element to a <p> tag
            var $replacement;
            if ($referencedTag.children().length === 1 && $referencedTag.children().first().is('p')) {
                $replacement = $referencedTag.children().first();
            }
            else {
                $replacement = $('<p>'+$referencedTag.html()+'</p>');
            }

            // Wrap content in a <sup> tag if not already and prepend content with origin link text
            if ($replacement.children().first().is('sup')) {
                $replacement.children().first().html($(this).text()+' '+$replacement.children().first().html());
            }
            else {
                $replacement.html('<sup>'+$(this).text()+' '+$replacement.html().trim()+'</sup>');
            }

            // Copy attributes
            var referencedTagAttributes = getTagAttributes($referencedTag);
            for (var attr in referencedTagAttributes) {
                $replacement.children().first().attr(attr, referencedTagAttributes[attr]);
            }

            // Replace element and move before next <h1>
            $referencedTag.replaceWith($replacement);
            $replacement.insertBefore($nextH1);
        }
    });
};

// Return the closest <h1> to an element
function getNextH1(el) {
    // Try to get next sibling
    var $nextH1 = el.nextAll('h1').get(0);

    // Switch element to its parent while not found
    while (_.isUndefined($nextH1)) {
        el = el.parent();
        // Return null if element has no parent
        if (_.isUndefined(el.get(0))) return null;
        $nextH1 = el.nextAll('h1').get(0);
    }

    return $nextH1;
};

// Return a tag name in lower case
function getTagName(el) {
    return el.get(0).name.toLowerCase();
}

// Return the tag attributes
function getTagAttributes(el) {
    return el.get(0).attribs;
}

function parse(html) {
    $ = cheerio.load(html);
}

function render() {
    return $.html();
}

// Process an HTML string
function clean(html) {
    // Convert to DOM using cheerio
    parse(html);

    // Cleanup elements
    retrieveFootnotes();
    setAnchorsId();
    cleanElements();
    cleanImagesInTitles();
    normalizeTitlesId();
    // Cleanup tables
    removeNestedTables();
    formatTables();
    cleanTableCells();

    return render();
};

module.exports = {
    clean: clean,
    parse: parse,
    render: render,
    cleanElements: cleanElements,
    setAnchorsId: setAnchorsId,
    retrieveFootnotes: retrieveFootnotes,
    normalizeTitlesId: normalizeTitlesId,
    removeNestedTables: removeNestedTables,
    formatTables: formatTables,
    cleanTableCells: cleanTableCells,
    cleanImagesInTitles: cleanImagesInTitles
};