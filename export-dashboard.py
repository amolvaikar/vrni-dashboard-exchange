import json
import re
import requests
import sys
import urllib3
from optparse import OptionParser
from types import SimpleNamespace

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


###############################################################
################ vRNI Session Management ######################
###############################################################
def open_vrni_public_api_session(url, user_id, password):
    try:
        session = requests.Session()

        session.auth = (user_id, password)

        data = '{"username":"' + user_id + '","password":"' + password + '", "domain": {'

        domain_type = "LOCAL"
        domain_value = ""

        if not "@local" in user_id:
            # Looks like ad/ldap login
            domain_type = "LDAP"
            domain_value = user_id.split("@")[1]

        data += '"domain_type" : "' + domain_type + '","value":"' + domain_value + '"}}'

        # Instead of requests.get(), you'll use session.get()
        response = session.post(url + "/api/ni/auth/token", data=data, verify=False,
                                headers={'content-type': 'application/json', 'accept': 'application/json'})
        # print response

        if response.status_code != 200:
            print("Failed to authenticate")
            return

        loaded_json = json.loads(response.content)
        session.headers["Authorization"] = "NetworkInsight " + loaded_json["token"]
        session.headers["Content-Type"] = "application/json"
        session.headers["Accept"] = "application/json"
        session.auth = None
        return session
    except requests.exceptions.ConnectionError as connection_exception:
        print("Failed to connect to " + url)
        print(connection_exception.message)
    return None


def open_vrni_private_api_session(url, user_id, password):
    try:
        session = requests.Session()

        session.auth = (user_id, password)

        # data = '{"username":"' + user_id + '","password":"' + password + '", "domain": "localdomain"}'

        data = '{"username":"' + user_id + '","password":"' + password + '", "domain": '
        domain_value = "localdomain"

        if not "@local" in user_id:
            domain_value = user_id.split("@")[1]

        data += '"' + domain_value + '"' + '}'
        print(data)

        # Instead of requests.get(), you'll use session.get()
        response = session.post(url + "/api/auth/login", data=data, verify=False,
                                headers={'content-type': 'application/json', 'accept': 'application/json'})
        print(response)
        # print response

        if response.status_code != 200:
            print("Failed to authenticate")
            return

        loaded_json = json.loads(response.content)
        print(loaded_json)
        session.headers["x-vrni-csrf-token"] = loaded_json["csrfToken"]
        session.headers["Content-Type"] = "application/json"
        session.headers["Accept"] = "application/json"
        session.auth = None
        return session
    except requests.exceptions.ConnectionError as connection_exception:
        print("Failed to connect to " + url)
        print(connection_exception.message)
    return None


###############################################################
################ Pinboard and Pin creation ####################
###############################################################
def get_query(query, name_and_param_dict, index):
    pattern = r"'([^']*)'"
    # Find all matches of the pattern in the sentence
    matches = re.findall(pattern, query)

    # Get the unique values
    unique_values = set(matches)
    for value in unique_values:
        if name_and_param_dict.get(value) is not None:
            query = query.replace(value, f"{{Parameter{index}}}")
        else:
            if len(name_and_param_dict) > 0:
                #print(len(name_and_param_dict))
                last_key, last_value = list(name_and_param_dict.items())[-1]
                # Check if the value is an integer
                if isinstance(last_value, int):
                    # Increase the value by 1
                    index = last_value + 1
                else:
                    print("Last value is not an integer.")
            name_and_param_dict[value] = index
            query = query.replace(value, f"{{Parameter{index}}}")
    return query


def get_pin_meta(pin_name, name_and_param_dict):
    for name, param in name_and_param_dict.items():
        if name in pin_name:
            pin_name = pin_name.replace(name, f"{{Parameter{param}}}")
    return pin_name


def export_queries_json_pre_db(pinboard):
    jsondata = {"pins": []}
    name_and_param_dict = dict()
    index = 1
    for pins in pinboard['pins']:
        jsondata['pins'].append({
            "pin_query": get_query(pins['query'], name_and_param_dict, index),
            "pin_name": get_pin_meta(pins['name'], name_and_param_dict),
            "pin_description": get_pin_meta(pins['name'], name_and_param_dict)
        })
    jsondata["default_board_name"] = get_pin_meta(pinboard['name'], name_and_param_dict)
    jsondata["description"] = get_pin_meta(pinboard['description'], name_and_param_dict)
    print("********************Dumping data*****************")
    print(json.dumps(jsondata))
    print("*************************************\n")
    print("File name of exported Dashboard Definition:" + pinboard['name'] + ".json")
    print("\n")
    with open(pinboard['name'] + ".json", 'a', encoding='utf-8') as f:
        json.dump(jsondata, f, ensure_ascii=False, indent=4)
        f.write("\n\n")
    pass

pass


def export_pinboard_pre_db(session, dashboard_name):
    response_get_all = session.get(url + "/api/ni/pinboards/", verify=False, headers={'content-type':'application/json', 'accept':'application/json'});
    #print(response_get_all)
    if response_get_all.status_code != 200:
        print("Failed to get Pinboards")
        return

    data = json.loads(response_get_all.content)
    #print(data)

    for pinboard in data["results"]:
        if dashboard_name.lower() == "ALL".lower():
            print("Adding:" + pinboard["name"])
            export_queries_json_pre_db(pinboard)
        elif dashboard_name.lower() == pinboard["name"].lower():
            print("Adding:" + pinboard["name"])
            export_queries_json_pre_db(pinboard)
    return None


def export_queries_json_post_db(session, query):
    response = session.get(url+"/api/search/query?searchString="+query, verify=False, headers={'content-type':'application/json', 'accept':'application/json'})
    #print(response)

    loaded_json = json.loads(response.content)
    #print(loaded_json)
    name_and_query_dict = dict()
    for applets in loaded_json["applets"]:
        default_board_name = applets["name"]
        description = applets["description"]
        for indApplets in applets["applets"]:
            if indApplets["type"] == "QUERY":
                name_and_query_dict[indApplets["id"]] = indApplets["querySets"][0]["query"]


    jsondata = {"pins": []}
    name_and_param_dict = dict()
    index = 1
    for name, query in name_and_query_dict.items():
        jsondata['pins'].append({
            "pin_query": get_query(query, name_and_param_dict, index),
            "pin_name": get_pin_meta(name, name_and_param_dict),
            "pin_description": get_pin_meta(name, name_and_param_dict)
        })

    jsondata["default_board_name"] = get_pin_meta(default_board_name, name_and_param_dict)
    jsondata["description"] = get_pin_meta(description,name_and_param_dict)
    print("********************Dumping data*****************")
    print(json.dumps(jsondata))
    print("*************************************\n")
    print("File name of exported Dashboard Definition:" + default_board_name + ".json")
    print("\n")
    with open(default_board_name + ".json", 'a', encoding='utf-8') as f:
        json.dump(jsondata, f, ensure_ascii=False, indent=4)
        f.write("\n\n")
    pass


def export_pinboard_post_db(session, dashboard_name):
    response_get_all = session.get(url + "/api/custom-dashboards/visible", verify=False, headers={'content-type':'application/json', 'accept':'application/json'});
    #print(response_get_all)
    if response_get_all.status_code != 200:
        print("Failed to get Dashboards")
        return

    data = json.loads(response_get_all.content)
    #print(data)
    name_and_query_dict = dict();
    for loaded_json in data:
        #print(loaded_json["name"])
        #print(dashboard_name)
        if loaded_json["name"].lower() == "Get Started".lower():
            continue
        elif dashboard_name.lower() == "ALL".lower():
            print("Adding:" + loaded_json["name"])
            name_and_query_dict[loaded_json["name"]] = loaded_json["query"]
        elif dashboard_name.lower() == loaded_json["name"].lower():
            print("Adding:" + loaded_json["name"])
            name_and_query_dict[loaded_json["name"]] = loaded_json["query"]
            break

    for name,query in name_and_query_dict.items():
        export_queries_json_post_db(session, query);
    return None


###############################################################
################ Data & Param validation ######################
###############################################################
def check_options(options):
    if options.dashboard_export_file is None:
        print("No file specified for export")
        return False
    return True


def is_valid_dashboard_json(json_object, use_public_api):
    json_object_is_valid = False
    try:
        for attr in ["default_board_name", "description", "pins"]:
            if hasattr(json_object, attr):
                json_object_is_valid = True
                continue
            else:
                print("Failed to find " + attr + " in input json")
                json_object_is_valid = False
                break

        if not json_object_is_valid:
            return json_object_is_valid

        if len(json_object.pins) > 20 and use_public_api:
            print(
                "WARNING: There are more than 20 pins in this definition, but vRNI version you are using allows only 20 pins per pinboard. "
                "This script will use only the first 20 pins from the file")

        for pin in json_object.pins:
            if not hasattr(pin, "pin_name") or not hasattr(pin, "pin_description") or not hasattr(pin, "pin_query"):
                print("Invalid pin definition " + pin)
                json_object_is_valid = False
                break
            else:
                json_object_is_valid = True
    except:
        print("Failed while loading the json from " + dashboard_export_file)
    return json_object_is_valid


###############################################################
################ Misc. Utils ##################################
###############################################################


def find_vrni_version(url, user_id, password):
    session = open_vrni_public_api_session(url, user_id, password)
    response = session.get(url + "/api/ni/info/version", verify=False)
    vrni_version = None
    if response.status_code == 200:
        loaded_json = json.loads(response.content)
        vrni_version = loaded_json["api_version"]
    session.close()
    return vrni_version


###############################################################
################ Main #########################################
###############################################################
def export_dashboard(url, user_id, password, dashboard_name, use_public_api):
    session = None
    if use_public_api:
        session = open_vrni_public_api_session(url, user_id, password)
    else:
        session = open_vrni_private_api_session(url, user_id, password)

    if session:

        if dashboard_name is None:
            dashboard_name = "ALL"

        if use_public_api:
            export_pinboard_pre_db(session, dashboard_name)
        else:
            export_pinboard_post_db(session, dashboard_name)


if __name__ == '__main__':

    parser = OptionParser()
    parser.add_option("-d", "--destination", dest="server",
                      help="vRNI Server IP/fqdn")

    parser.add_option("-u", "--user",
                      dest="uid",
                      help="vRNI User")

    parser.add_option("-p", "--password",
                      dest="password",
                      help="vRNI User's password")

    # parser.add_option("-f", "--file",
    #                   dest="dashboard_export_file",
    #                   help="Dashboard definition file name to use for exporting the dashboard")

    parser.add_option("-n", "--name",
                      dest="dashboard_name",
                      help="[Optional] Name of the dashboard to be exported. If nothing is specified All dashboards will be exported to the file")

    (options, args) = parser.parse_args()

    if options.server is None or options.uid is None or options.password is None:
        parser.print_help()
        print("Insufficient arguments")
        sys.exit(1)

    # if not check_options(options):
    #     sys.exit(1)

    url = "https://" + options.server
    user_id = options.uid
    password = options.password
    dashboard_name = options.dashboard_name
    #dashboard_export_file = options.dashboard_export_file
    # dashboard_arguments = options.dashboard_arguments

    # Find which vRNI version we are dealing with here
    vrni_version = find_vrni_version(url, user_id, password)
    if vrni_version is None:
        print("Unable to find vRNI version, terminating.")
        sys.exit(1)

    # Find which API we are supposed to use, based on vRNI version
    [major_version, minor_version, _] = vrni_version.split(".")
    use_public_api = False
    if int(major_version) <= 6:
        if int(minor_version) < 9:
            use_public_api = True

    export_dashboard(url, user_id, password, dashboard_name, use_public_api)
