import sys
import requests
import json
from optparse import OptionParser
import urllib3
from types import SimpleNamespace

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


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


def create_pinboard_pre_69(session, pinboard_name, pinboard_description):
    body = '''{{"name": "{0}", "description": "{1}"}}'''.format(pinboard_name, pinboard_description)
    response = session.post(url + "/api/ni/pinboards", data=body, verify=False)
    if response.status_code == 201:
        loaded_json = json.loads(response.content)
        return loaded_json["id"]
    print(
        "Failed to create pinboard, please check if the pinboard already exists or if you have used admin/member login credentials")
    return None


def create_pinboard_post_69(session, dashboard_name, dashboard_description):
    body = '''{{"name": "{0}", "description": "{1}"}}'''.format(dashboard_name, dashboard_description)
    response = session.post(url + "/api/custom-dashboards", data=body, verify=False)
    if response.status_code == 201:
        loaded_json = json.loads(response.content)
        return loaded_json["modelKey"]
    print(
        "Failed to create dashboard, please check if the dashboard already exists or if you have used admin/member login credentials")
    return None


def add_pin_to_pinboard_pre_69(session, pinboard_id, pin_name, pin_query):
    body = '''{{"name": "{0}", "query": "{1}"}}'''.format(pin_name, pin_query)
    response = session.post(url + "/api/ni/pinboards/{}/pins".format(pinboard_id), data=body, verify=False)
    if response.status_code != 201:
        print("Failed to create pin for {}".format(pin_name))
    loaded_json = json.loads(response.content)
    return


def add_pin_to_pinboard_post_69(session, dashboard_id, pin_name, pin_query):
    body = '{"id":"' + pin_name + '","query":"' + pin_query + '", "isApplet": false, "dataBlob": "{}", "entities":[]}'
    print(body)
    response = session.post(url + "/api/custom-dashboards/{}/pins".format(dashboard_id), data=body, verify=False)
    print(response)
    loaded_json = json.loads(response.content)
    return


def check_options(options):
    if options.dashboard_file is not None and options.online_dashboard_file is not None:
        print("Cant use online as well as offline file at same time")
        return False
    return True


def read_dashboard_json(dashboard_file):
    with open(dashboard_file, "r") as input_file:
        json_text = input_file.read()

    dashboard_json_object = None
    try:
        dashboard_json_object = json.loads(json_text, object_hook=lambda d: SimpleNamespace(**d))
    except:
        print("Failed while loading the json from " + dashboard_file)
    return dashboard_json_object


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
            print("WARNING: There are more than 20 pins in this definition, but vRNI version you are using allows only 20 pins per pinboard. "
                  "This script will use only the first 20 pins from the file")

        for pin in json_object.pins:
            if not hasattr(pin, "pin_name") or not hasattr(pin, "pin_description") or not hasattr(pin, "pin_query"):
                print("Invalid pin definition " + pin)
                json_object_is_valid = False
                break
            else:
                json_object_is_valid = True
    except:
        print("Failed while loading the json from " + dashboard_file)
    return json_object_is_valid


def find_vrni_version(url, user_id, password):
    session = open_vrni_public_api_session(url, user_id, password)
    response = session.get(url + "/api/ni/info/version", verify=False)
    vrni_version = None
    if response.status_code == 200:
        loaded_json = json.loads(response.content)
        vrni_version = loaded_json["api_version"]
    session.close()
    return vrni_version


def create_dashboard(url, user_id, password, dashboard_json_object, dashboard_name, use_public_api):
    session = None
    if use_public_api:
        session = open_vrni_public_api_session(url, user_id, password)
    else:
        session = open_vrni_private_api_session(url, user_id, password)

    if session:
        # create the dashboard
        dashboard_id = None
        if dashboard_name is None:
            dashboard_name = dashboard_json_object.default_board_name

        if use_public_api:
            dashboard_id = create_pinboard_pre_69(session, dashboard_name, dashboard_json_object.description)
        else:
            dashboard_id = create_pinboard_post_69(session, dashboard_name, dashboard_json_object.description)

        for pin in dashboard_json_object.pins:
            if use_public_api:
                add_pin_to_pinboard_pre_69(session, dashboard_id, pin.pin_name, pin.pin_query)
            else:
                add_pin_to_pinboard_post_69(session, dashboard_id, pin.pin_name, pin.pin_query)

def download_dashboard_file(sourceurl, destinationfile = "./temp_dashboard.json"):
    response = requests.get(sourceurl)
    if response.status_code == 200:
        with open(destinationfile, 'wb') as file:
            file.write(response.content)
        print("Online Dashboard File downloaded successfully.")
    else:
        print("Failed to download the online Dashboard file.")
        return None
    return destinationfile


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

    parser.add_option("-f", "--file",
                      dest="dashboard_file",
                      help="Dashboard definition file to use for creating the new dashboard")

    parser.add_option("-o", "--onlinefile",
                      dest="online_dashboard_file",
                      help="URL for Dashboard definition file to use for creating the new dashboard. Can be a file from the pinboard exchange repo")

    parser.add_option("-n", "--name",
                      dest="dashboard_name",
                      help="[Optional] Name to be used for the dashboard")

    (options, args) = parser.parse_args()

    if options.server is None or options.uid is None or options.password is None:
        parser.print_help()
        print("Insufficient arguments")
        sys.exit(1)

    if not check_options(options):
        sys.exit(1)

    if options.online_dashboard_file is not None:
        options.dashboard_file = download_dashboard_file(options.online_dashboard_file)

    url = "https://" + options.server
    user_id = options.uid
    password = options.password
    dashboard_name = options.dashboard_name
    dashboard_file = options.dashboard_file

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

    dashboard_json_object = read_dashboard_json(dashboard_file)
    if not is_valid_dashboard_json(dashboard_json_object, use_public_api):
        print("Dashboard json is invalid, cant create Dashboard")
        sys.exit(1)

    create_dashboard(url, user_id, password, dashboard_json_object, dashboard_name, use_public_api)
