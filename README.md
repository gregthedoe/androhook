# AndroHook
A frida based hooking framework for android devices used mainly for app research.

It includes its own javascript wrapper for java objects called $J, which allows better handling for JAVA objects via reflection.

For example:
```
Java.perform(function () {
    var $class1 = $J(Java.use('com.example.class1'));
    console.log($class1.getFieldValue('field1').getFieldValue('field2'));
});
```

## Install

### Install dependencies

Installation requires nodejs to be in user's path.

For linux:
```
sudo apt install nodejs
```
For windows:
https://nodejs.org/en/download/current/

### Installing AndroHook

```
git clone https://github.com/gregthedoe/androhook.git
cd androhook
pip install . 

# For SSL interception support, use:
pip install .[ssl]
```

## Usage
```
adb shell /data/local/tmp/frida-server &

# For simple injection
injector.py -p com.example.package -s sample_script.js

# For SLL interception (if installed)
intercept_ssl.py --flow vending.flow com.android.vending 
```
