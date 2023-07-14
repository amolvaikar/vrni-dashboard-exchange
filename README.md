## Background
Aria Operations for Networks (a.k.a. vRNI) has a very useful functionality of customizable dashboards/pinboards.
Using this, one can create dashboards/pinboards for various themes/use-cases, like say, monitoring the changes to the NSX-T environment, or monitoring flow metrics for specific applications and their tiers.
Formulating useful dashboards/pinboards for various use-cases, personas, workflows, etc., and actually creating them manually is tedious, esp. if you have to do it on multiple vRNI setups in your environment.
So the goal of the dashboard/pinboard exchange is:
1. Provide dashboard/pinboard definitions for various use-cases so that everyone can use them, learn from them, extend them, and share them with others.
2. Provide a script that will use the dashboard/pinboard definitions and create them on your vRNI setup by using the right APIs depending on the version of vRNI.
3. Provide a script that will use the existing dashboard/pinboard created on a vRNI setup and export them into the format of dashboard definitions. These definitions can be used to create dashboards on vRNI setups.

## Why we do use the words dashboard/pinboards interchangeably?
1. vRNI version up to 6.8.0 calls the custom dashboards "Pinboards"
2. vRNI 6.9.0 onwards we call them "Customizable Dashboards"

## How to use the scripts and the dashboard definitions:
The script for creating the dashboards is written in Python and works with Python 3.
Download the "create-dashboard.py" on any system that has Python3.
The following snippets show how to trigger the script:

1. The dashboard definition JSON is available on the local file system:
```commandline
$ python3 create-dashboard.py -d my-vrni-setup-fqdn-or-ip -u admin@local -p MyVRNIPassword -f ./significant-changes.json
```

2. The dashboard definition json can be used directly from github repo too, no need to explicitly download it (please note the use of raw file link):
```commandline
$ python3 create-dashboard.py -d my-vrni-setup-fqdn-or-ip -u admin@local -p MyVRNIPassword -o https://raw.githubusercontent.com/amolvaikar/vrni-dashboard-exchange/main/pinboards/troubleshooting/significant-changes.json
```

## Parameterisation of the dashboard JSON
This tool allows you to create and use parameterized dashboard JSONs.
For e.g., let's say you want to create a JSON for application networking metrics, and it involves queries that refer to
specific applications, like:

```cpu usage, memory usage, read latency, write latency of host where vm in (vm where application like 'MyApplication1')```

Note that in the above query, the application name 'MyApplication1' has been used explicitly.
But if you have to use this JSON for 10 different applications, would you have to create 10 different JSON files for specific applications?
That would be too tedious, plus such a JSON would not be shareable with others since it wouldn't work for them.
Thus, this tool lets you define the query using parameters that can then be replaced during the execution of the script.
So, the above query would be added to the JSON in the following format:

```cpu usage, memory usage, read latency, write latency of host where vm in (vm where application like '{ApplicationName}')```

Notice the use of `{ApplicationName}` in the above query.
A JSON which uses parameterized queries can be used as shown in this invocation:
```commandline
$ python3 create-dashboard.py -d my-vrni-setup-fqdn-or-ip -u admin@local -p MyVRNIPassword -f ./application-network.json -a "ApplicationName=MyApplication1, SomeOtherParam=value1"
```

If you have an existing dashboard/pinboard you can export it as a dashboard definition. This dashboard definition can then be used as input to the create-dashboard.py to create a dashboard on the same vRNI setup or other vRNI setups.
In order to create a dashboard definition from an existing dashboard download the "export-dashboard.py" on any system that has Python3.
The following snippets show how to trigger the script:

1. Given the name of a dashboard/pinboard the dashboard definition JSON will be created on the local file system:
```commandline
$ python3 export-dashboard.py -d my-vrni-setup-fqdn-or-ip -u admin@local -p MyVRNIPassword -n "name-of-the-dashboard-to-be-exported"
```
At the end of execution, it will display the following message

```File name of exported Dashboard Definition:Overall Flow Summary.json```

2. If we want to export all the dashboard/pinboard as dashboard definition JSONs use the following:
```commandline
$ python3 export-dashboard.py -d my-vrni-setup-fqdn-or-ip -u admin@local -p MyVRNIPassword
```
This will export all the dashboard definition JSONs as separate files.

## Dashboard Definitions
The dashboard definitions will be update on a regular basis based on different use-cases. Currently all the dashboard definitions have been kept under the pinboards folder under different categories.
Users can leverage the existing dashboard definitions to create dashboards and gain insights into their environment.

## Demo
Following is a link to a short demo covering the functionalities of the Dashboard Exchange

[Demo link](https://onevmw-my.sharepoint.com/:v:/g/personal/dbaheti_vmware_com/EWdmNUAsUSFNoGUcLIZChCMBzO2Emhid6PJxdlH1M4bUtQ?e=O1ONpD)
