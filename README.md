### Background
Aria Operations for Networks (a.k.a. vRNI) has a very useful functionality of customizeable dashboards/pinboards.
Using this, one can create dashboards/pinboards for various themes/usecases, like say, monitoring the changes to NSX-T environment, or monitoring flow metrics for specific application and its tiers.
Formulating useful dashboards/pinboards for various usecases, personas, workflows etc., and actually creating them manually is tedious, esp. if you have to do it on multiple vRNI setups in your environment.
So the goal of the dashboard/pinboard exchange is:
1. Providing dashboard/pinboard definitions for various usecases so that everyone can use them, learn from them, extend them and share with others.
2. Providing a script that will use the dashboard/pinboard definitions and create them on your vRNI setup by using the right APIs depending on the version of vRNI.

### Why we do use the words dashboard/pinboards interchangeably?
1. vRNI version up to 6.8.0 calls the custom dashboards as "Pinboards"
2. vRNI 6.9.0 onwards we call them "Customizeable Dashboards"

### How to use the scripts and the dashboard definitions:
The script for creating the dashboards is written in Python and works with Python 3.
Download the "create-dashboard.py" on any system that has Python3.
The following snippets shows how to trigger the script:

1. The dashboard definition json is available on local file system:
```
$ python3 create-dashboard.py -d my-vrni-setup-fqdn-or-ip -u admin@local -p MyVRNIPassword -f ./significant-changes.json
```

2. The dashboard definition json is to be used directly from github repo (please note the use of raw file link):
```
$ python3 create-dashboard.py -d my-vrni-setup-fqdn-or-ip -u admin@local -p MyVRNIPassword -o https://raw.githubusercontent.com/amolvaikar/vrni-dashboard-exchange/main/pinboards/troubleshooting/significant-changes.json
```
