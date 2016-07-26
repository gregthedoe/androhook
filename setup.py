from setuptools import setup

setup(
        name='androhook',
        version='0.1',
        url='https://github.com/gregthedoe/androhook',
        license='MIT',
        author='Greg',
        author_email='',
        description='A frida based hooking framework for android devices used mainly for app research',
        packages=['androhook', 'androhook.network', 'androhook.network.flow_writers'],
        include_package_data=True,
        scripts=['scripts/intercept_ssl.py'],
        install_requires=[
            'frida',
            'mitmproxy>=0.17',
            'datetime'
        ]
)
