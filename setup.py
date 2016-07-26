from distutils.core import setup

setup(
        name='androhook',
        version='0.1',
        packages=['androhook', 'androhook.network', 'androhook.network.flow_writers'],
        url='https://github.com/gregthedoe/androhook',
        license='MIT',
        author='greg',
        author_email='',
        description='A frida based hooking framework for android devices used mainly for app research'
)
