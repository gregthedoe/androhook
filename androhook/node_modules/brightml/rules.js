module.exports = {
    // List of attributes that require a schema filtering
    schemaAttributes: [ 'scr', 'href' ],

    // Allowed schema for schemaAttributes
    allowedSchemes: [
        'http://', 'https://', 'ftp://', 'mailto://', '#', '/', './', '../' , 'data:'
    ],

    // List of attributes allowed for all elements
    allowedAttributes: [
        'id', 'style', 'class', 'type'
    ],

    // List of allowed empty tags
    allowedEmpty: [
        'img',
        'th', 'td'  // Allow keeping <table> elements formatting
    ],

    // Allowed tags and their attributes
    allowed: {
        a:      ['target', 'href', 'title'],
        abbr:   ['title'],
        address: [],
        area:   ['shape', 'coords', 'href', 'alt'],
        article: [],
        aside:  [],
        audio:  ['autoplay', 'controls', 'loop', 'preload', 'src'],
        b:      [],
        bdi:    ['dir'],
        bdo:    ['dir'],
        big:    [],
        blockquote: ['cite'],
        br:     [],
        caption: [],
        center: [],
        cite:   [],
        code:   [],
        col:    ['align', 'valign', 'span', 'width'],
        colgroup: ['align', 'valign', 'span', 'width'],
        dd:     [],
        del:    ['datetime'],
        details: ['open'],
        div:    [],
        dl:     [],
        dt:     [],
        em:     [],
        font:   ['color', 'size', 'face'],
        footer: [],
        h1:     [],
        h2:     [],
        h3:     [],
        h4:     [],
        h5:     [],
        h6:     [],
        header: [],
        hr:     [],
        i:      [],
        img:    ['src', 'alt', 'title', 'width', 'height'],
        ins:    ['datetime'],
        li:     [],
        mark:   [],
        nav:    [],
        ol:     [],
        p:      [],
        pre:    [],
        s:      [],
        section:[],
        small:  [],
        span:   [],
        sub:    [],
        sup:    [],
        strong: [],
        table:  ['width', 'border', 'align', 'valign'],
        tbody:  ['align', 'valign'],
        td:     ['width', 'colspan', 'align', 'valign'],
        tfoot:  ['align', 'valign'],
        th:     ['width', 'colspan', 'align', 'valign'],
        thead:  ['align', 'valign'],
        tr:     ['rowspan', 'align', 'valign'],
        tt:     [],
        u:      [],
        ul:     [],
        video:  ['autoplay', 'controls', 'loop', 'preload', 'src', 'height', 'width']
    }
};
