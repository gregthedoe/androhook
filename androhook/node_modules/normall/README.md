NormALL - Normalize all things !
=======

JS library to normalize `filenames`, `usernames`, ...


### normall(str)

Apply basic normalization: `latenize` then strip `ascii` then `trim`


### normall.filename(str)

Normalize `str` for use in filename: `base` then strip `illegal filename chars` then `" " => "_"`

:Warning: This does not expect extensions, and normalizes the "name" part of the filename


### normall.ascii(str)

Strips non ascii chars from string


### normall.latenize(str)

Converts all non latin characters to latin characters. Strips accents, ...


### normall.accents(str)

Alias to `normall.latenize`


### normall.username(str)

Normalizes `str` to be used as a username (strips accents, ...)
