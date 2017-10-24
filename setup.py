#!/usr/bin/python

from setuptools import setup

setup(
        name='androhook',
        version='0.2',
        url='https://github.com/gregthedoe/androhook',
        license='MIT',
        author='Greg',
        author_email='',
        description='A frida based hooking framework for android devices used mainly for app research',
        packages=['androhook', 'androhook.network', 'androhook.network.flow_writers'],
        include_package_data=True,
        scripts=['scripts/intercept_ssl.py', 'androhook/injector.py'],
        install_requires=[
            'frida',
            'datetime'
        ],
        extras_require={
            'ssl': ['mitmproxy>=0.17']
        }
)
