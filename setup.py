from setuptools import setup

setup(
    name='flask-password',
    version='0.5.0',
    packages=['flask_oauth', 'flask-password'],
    url='https://github.com/viniciuschiele/flask-password',
    license='Apache 2.0',
    author='Vinicius Chiele',
    author_email='vinicius.chiele@gmail.com',
    description='Password hashing for Python 3+',
    keywords=['flask', 'password'],
    install_requires=['flask==0.10.1'],
    classifiers=[
        'Development Status :: 4 - Beta',
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
