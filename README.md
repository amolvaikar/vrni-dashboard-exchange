## Background
Aria Operations for Networks (a.k.a. vRNI) has a very useful functionality of customizeable dashboards/pinboards.
Using this, one can create dashboards/pinboards for various themes/usecases, like say, monitoring the changes to NSX-T environment, or monitoring flow metrics for specific application and its tiers.
Formulating useful dashboards/pinboards for various usecases, personas, workflows etc., and actually creating them manually is tedious, esp. if you have to do it on multiple vRNI setups in your environment.
So the goal of the dashboard/pinboard exchange is:
1. Providing dashboard/pinboard definitions for various usecases so that everyone can use them, learn from them, extend them and share with others.
2. Providing a script that will use the dashboard/pinboard definitions and create them on your vRNI setup by using the right APIs depending on the version of vRNI.

## Why we do use the words dashboard/pinboards interchangeably?
1. vRNI version up to 6.8.0 calls the custom dashboards as "Pinboards"
2. vRNI 6.9.0 onwards we call them "Customizeable Dashboards"

## How to use the scripts and the dashboard definitions:
The script for creating the dashboards is written in Python and works with Python 3.
Download the "create-dashboard.py" on any system that has Python3.
The following snippets shows how to trigger the script:

1. The dashboard definition json is available on local file system:
```commandline
$ python3 create-dashboard.py -d my-vrni-setup-fqdn-or-ip -u admin@local -p MyVRNIPassword -f ./significant-changes.json
```

2. The dashboard definition json can be used directly from github repo too, no need to explicitly download it (please note the use of raw file link):
```commandline
$ python3 create-dashboard.py -d my-vrni-setup-fqdn-or-ip -u admin@local -p MyVRNIPassword -o https://raw.githubusercontent.com/amolvaikar/vrni-dashboard-exchange/main/pinboards/troubleshooting/significant-changes.json
```

## Parameterisation of the dashboard json
This tool allows you to create and use parameterised dashboard jsons.
For e.g., lets say you want to create a json for application networking metrics, and it involves queries that refer to
specific applications, like:

```cpu usage, memory usage, read latency, write latency of host where vm in (vm where application like 'MyApplication1')```

Note that in the above query, application name 'MyApplication1' has been used explicitly.
But if you have to use this json for 10 different applications, would you have to create 10 different json files for specific applications?
That would be too tedious, plus such a json would not be shareable with others since it wouldnt work for them.
Thus, this tool lets you define the query using parameters which can then be replaced during execution of the script.
So, the above query would be added to the json in the following format:

```cpu usage, memory usage, read latency, write latency of host where vm in (vm where application like '{ApplicationName}')```

Notice the use of `{ApplicationName}` in the above query.
A json which uses parameterised queries can be used as shown in this invocation:
```commandline
$ python3 create-dashboard.py -d my-vrni-setup-fqdn-or-ip -u admin@local -p MyVRNIPassword -f ./application-network.json -a "ApplicationName=MyApplication1, SomeOtherParam=value1"
```