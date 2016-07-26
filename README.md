# AndroHook
A frida based hooking framework for android devices used mainly for app research.

## Install
```
git clone https://github.com/gregthedoe/androhook.git
cd androhook
pip install . 
```

## Usage
```
adb shell /data/local/tmp/frida-server &
intercept_ssl.py --flow vending.flow com.android.vending 
```
