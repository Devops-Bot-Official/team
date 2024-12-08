from setuptools import setup, find_packages

# Helper function to load dependencies from requirements.txt
def load_requirements(filename):
    with open(filename, 'r') as f:
        return f.read().splitlines()

setup(
    name='devops-boti-dev-server',
    version='0.1',
    description='DevOps Bot: An IaaS tool for managing infrastructure and cloud resources.',
    author='Nikhil konda',
    author_email='nikhilkonda45@gmail.com',
    url='https://github.com/Devops-Bot-Official',
    packages=find_packages(),
    install_requires=load_requirements('requirements.txt'),
    entry_points='''
        [console_scripts]
        dob=dev_test_server.cli:cli
    ''',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
)


