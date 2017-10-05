from setuptools import setup, find_packages
setup(
    name="docker_registry_client",
    version="0.4",
    description='Client for Docker Registry V1',
    author='John Downs',
    author_email='john.downs@yodle.com',
    license="Apache License 2.0",
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: System :: Software Distribution',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 2.7'],
    keywords='docker docker-registry REST',
    packages=find_packages(),
    install_requires=['requests>=2.4.3',
                      'flexmock'],
)
