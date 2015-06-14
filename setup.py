from setuptools import setup

setup(
    name='flask-password',
    version='1.0.0',
    packages=['flask_password'],
    url='https://github.com/viniciuschiele/flask-password',
    license='Apache 2.0',
    author='Vinicius Chiele',
    author_email='vinicius.chiele@gmail.com',
    description='Password hashing for Python 3+',
    keywords=['flask', 'password', 'hash', 'hashing'],
    install_requires=['flask>=0.10.1'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: Implementation :: CPython'
    ]
)
