#!/usr/bin/env python

# Copyright (c) 2017-2019 Nagios Enterprises, LLC.

# This code uses only standard-library functions available in Python 2.6.6 (the 
# default for CentOS 6).

import sys # exit()
import optparse 
from os.path import expanduser # Handles the conflict between ~ as -inf and ~ as root directory
import subprocess
import urllib # Just for urlencode()
import json
import shlex
import signal
from copy import copy

# Globals
__PLUGIN_NAME__ = "check_docker.py"
__VERSION__ = "1.1.1"
options = ""

#could be made to inherit from enum, but not really necessary.
class check_status():
    OK = 0
    WARNING = 1
    CRITICAL = 2
    UNKNOWN = 3

# Dictionary of valid check options mapped to their handler function names, ctrl+f for "valid_checks"

# Add program options here. Defaults are already populated.
def get_options():
    version = '%s, Version %s. See --help for more info.' % (__PLUGIN_NAME__, __VERSION__)
    global options
    parser = optparse.OptionParser()

    # Stored strings
    parser.add_option("-H", "--host", default="", 
        help="The host URL for your Docker daemon. If this plugin is run locally, it should be "
             "something like 'http:/v1.35/'. If it's run remotely, it should be of the form "
             "'http[s]://ip.ip.ip.ip[:port]/'")
    parser.add_option("-s", "--socket", default="",
        help="The docker unix socket (local connection only). This should be of the form "
             "'/var/run/docker.sock'")
    parser.add_option("-t", "--timeout", default="0", 
        help="Set the timeout duration in seconds. Defaults to never timing out.")
    parser.add_option("-C", "--containers", 
        help="A (quote-enclosed, comma-delimited) list of container names/ids. If --networks is "
             "set, this will be ignored.")
    parser.add_option("-N", "--networks", 
        help="A (quote-enclosed, comma-delimited) list of network names/ids. If this is set, "
             "--containers will be ignored.")
    parser.add_option("-I", "--images",
        help="A (quote-enclosed, comma-delimited) list of image names (with tags). If this is set, "
             "--containers/--networks will be ignored. Ex: -I 'ubuntu:latest,tomcat'")
    parser.add_option("-w", "--warning", default="50", 
        help="Set the warning threshold.")
    parser.add_option("-c", "--critical", default="75", 
        help="Set the critical threshold.")
    parser.add_option("--perfdata-max", default="", 
        help="Set the maximum value (used by performance data grapher).")
    parser.add_option("--perfdata-min", default="", 
        help="Set the minimimum value (used by performance data grapher).")
    parser.add_option("--check-type", 
        help="Choose the type of check. Currently implemented: containers_exist, "
             "containers_running, containers_healthy, containers_cpu, containers_memory")
    parser.add_option("--cert", default="", 
        help="The full path to the TLS v1.0 cert to access your secure docker port (remote "
             "connection only).")
    parser.add_option("--key", default="", 
        help="The full path to the TLS v1.0 key to access your secure docker port (remote "
             "connection only).")
    parser.add_option("--cacert", default="",
        help="The full path to the TLS v1.0 cacert to access your secure docker port (remote "
             "connection only).")
    parser.add_option("--memory-unit", default="B", 
        help="Allows you to set a unit of measure for memory calculation. "
             "Valid inputs: B, KiB, MiB, GiB")

    # Booleans
    parser.add_option("-v", "--verbose", action="store_true", default=False, 
        help="Print more verbose error messages.")
    parser.add_option("-V", "--version", action="store_true", default=False, 
        help="Print the version number and exit.")
    parser.add_option("-a", "--all", action="store_true", default=False, 
        help="Instead of specifying names or IDs, perform checks on all containers (even ones "
             "that aren't running). If this is set, --containers and --networks are ignored.")
    parser.add_option("-l", "--list-bad-containers", action="store_true", default=False, 
        help="List the containers that aren't running/healthy/under-usage-limits in long output.")
    parser.add_option("--total-usage", action="store_true", default=False, 
        help="Calculate total usage in addition to per-container usage. Uses the first warning "
             "and critical thresholds")
    parser.add_option("--separate-containers", action="store_true", default=False,
        help="For networks and images, show each container as though it was specified on the command line "
             "(rather than giving results per-network or per-image).")
    parser.add_option("--total-average", action="store_true", default=False, 
        help="Calculate average usage for all containers/networks. Uses the first warning and "
             "critical thresholds, or the second if total-usage is used.")
    parser.add_option("--networks-use-avg", action="store_true", default=False, 
        help="Calculate the average (mean) usage for networks instead of total usage.")
    parser.add_option("-p", "--percentage", action="store_true", default=False, 
        help="Calculate running/healthy as a percentage of all selected containers rather than a "
             "strict count.")
    parser.add_option('--count-unhealthy-containers', action="store_true", default=False,
        help="When running health checks, have thresholds represent the number of unhealthy "
             "containers instead of the number of healthy containers")
    parser.add_option("--missing-healthcheck-is-counted", action="store_true", default=False,
        help="No effect unless check-type is containers_healthy. Counts containers which are"
             "missing their healthcheck towards the warning/critical thresholds")
    parser.add_option("--no-check-is-healthy", action="store_true", dest="missing_healthcheck_is_counted", default=False, 
        help="Alias for --missing-healthcheck-is-counted.")
    parser.add_option("--ignore-no-healthcheck", action="store_true", default=False, 
        help="Exclude containers without healthchecks from the tally.")
    parser.add_option("--no-individual-checks", action="store_true", default=False, 
        help="For usage statistics, only calculate warning/critical off aggregate metrics like "
             "total/average usage.")
    parser.add_option("--timeout-is-critical", action="store_true", default=False,
        help="When the check times out before completing, plugin returns CRITICAL status instead of UNKNOWN")
    parser.add_option("--debug", action="store_true", default=False)
    # Help is implemented by default by optparse

    options, _ = parser.parse_args()
    
    # Argument/option checking occurs here.
    if options.version or len(sys.argv) == 1:
        nagios_exit(version, check_status.OK)

    global valid_checks
    check_types = valid_checks.keys()
    if not options.check_type:
        nagios_exit("No check type specified. Check types: " + str(check_types), 3)
    options.check_type = options.check_type.lower()
    if options.check_type not in check_types:
        nagios_exit("Check type not supported.", 3, "", "Check types: " + str(check_types))
    if options.check_type == "containers_cpu":
        options.percentage = True

    if options.perfdata_min > options.perfdata_max:
        nagios_exit("--perfdata-max must be larger than --perfdata-min", 3)

    if not options.host:
        nagios_exit("Please specify the host address of your docker API", 3)

    if options.check_type != "containers_memory":
        options.memory_unit = "%"

    if options.check_type == "containers_memory" and options.memory_unit:
        options.warning = scale_threshold_list(options.warning, options.memory_unit)
        options.critical = scale_threshold_list(options.critical, options.memory_unit)

    if options.memory_unit not in unit_dict.keys():
        nagios_exit("Invalid unit. Pick one of " + str(unit_dict.keys()), check_status.UNKNOWN)

    # Make the cURL options command-line-ready.
    if options.host[-1] != "/":
        options.host += "/"
    if options.socket:
        options.socket = "--unix-socket " + options.socket
    if options.cert:
        options.cert = "--cert " + options.cert
    if options.key:
        options.key = "--key " + options.key
    if options.cacert:
        options.cacert = "--cacert " + options.cacert

    set_timeout(int(options.timeout))

    return options

def choose_checks(options):

    attributes_count = 1
    if not options.all:
        if options.images:
            selection_type = "images"
            selection = options.images.split(',')
            
        elif options.networks:
            selection_type = "networks"
            selection = options.networks.split(",")

        elif options.containers:
            selection_type = "containers"
            selection = options.containers.split(",")

        else:
            options.all = True
            selection_type = 'all'
            selection = { 'total_usage' : [] }

        attributes_count = len(selection)
        if attributes_count == 0:
            nagios_exit("No container IDs selected", check_status.UNKNOWN, "", 
                "Either no container IDs were entered, or the container names, network IDs, and "
                "container IDs listed all had no associated containers.")
    else:
        selection_type = 'all'
        selection = { 'total_usage' : [] }

    if options.debug:
        print selection_type
        print selection
        print "End selection + type"

    if not options.all:
        # This is a switch!
        selection_function = {
            'containers': containers_list_to_dict,
            'networks': networks_list_to_dict,
            'images': images_list_to_dict,
        }

        selection = selection_function[selection_type](selection)

        if not selection:
            nagios_exit("None of the listed containers/networks exist!", check_status.CRITICAL, "",
                "Plugin tried to find matching containers from IDs/names specified by -C/-N/-I, but none were found on the docker machine.")

    if options.total_usage or options.all: 
        selection['total_usage'] = []
    if options.total_average: 
        selection['average_usage'] = []

    if options.debug:
        print "selection before assigning thresholds"
        print selection

    check_data = get_threshold_maps(options.warning, options.critical, selection)

    if options.debug:
        print "threshold maps"
        print check_data

    if options.separate_containers:
        selection_type = 'containers'
        check_data = separate_checks(check_data)

    return check_data


# This should get called in options processing only!
# timeout should default to zero

def timeout_handler(signal, frame):
    global options
    timeout_status = check_status.UNKNOWN
    if options.timeout_is_critical:
        timeout_status = check_status.CRITICAL
    nagios_exit("check timed out", timeout_status)

def set_timeout(seconds):
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(seconds)

def scale_threshold(threshold, multiplier):
    out_str = ""
    if not threshold:
        return out_str
    if threshold[0] == "@":
        out_str = "@"
        threshold = threshold[1]
    bounds = threshold.split(":")
    for index, bound in enumerate(bounds):
        try:
            bounds[index] = float(bound)
            bounds[index] *= multiplier
            bounds[index] = str(bounds[index])
        except:
            pass
    out_str += ":".join(bounds)
    return out_str

def scale_threshold_list(list_in, unit_in):
    global unit_dict
    multiplier = unit_dict[unit_in]
    list_in = list_in.split(",")
    for index, threshold in enumerate(list_in):
        list_in[index] = scale_threshold(threshold, multiplier)
    list_in = ','.join(list_in)
    return list_in

# Takes the message to print to stdout and the exit code,
# prints, then exits.
def nagios_exit(out, code, perfdata="", verbose_out=""):
    if options.debug: print "hit " + "nagios_exit"
    prefix = code_to_status(code)
    out = prefix + ": " + out
    if options.verbose:
        out += " " + verbose_out + "\n"
    out += perfdata
    print out
    exit(code)

class CheckData:
    def __init__(self, name, warning_text, critical_text, container_IDs):
        self.name = name
        # Raw text is saved so that the thresholds can be printed when writing out perfdata
        self.warning_text = warning_text
        self.warning_parsed = threshold_string_to_tuple(warning_text)
        self.critical_text = critical_text
        self.critical_parsed = threshold_string_to_tuple(critical_text)
        self.container_IDs = container_IDs
        self.value = 0

    def setValue(self, value):
        self.value = value

    def setRC(self, value):
        self.RC = value

    def to_individual_containers(self):
        ret = dict((x, copy(self)) for x in self.container_IDs)

        for new_name in ret.keys():
            ret[new_name].name = new_name
            ret[new_name].container_IDs = [new_name]
        return ret

    def scale(self, uom):
        self.warning_text = scale_threshold(self.warning_text, 1/float(unit_dict[uom.lower()]))
        self.warning_parsed = threshold_string_to_tuple(self.warning_text)
        self.critical_text = scale_threshold(self.critical_text, 1/float(unit_dict[uom.lower()]))
        self.critical_parsed = threshold_string_to_tuple(self.critical_text)
        self.value = float(scale_threshold(str(self.value), 1/float(unit_dict[uom.lower()])))

    def __str__(self):
        self_dict = {'name': self.name, 'warning': self.warning_parsed, 'critical': self.critical_parsed, 'containers': self.container_IDs, 'value': self.value}
        return str(self_dict)

    def __repr__(self):
        return str({'name': self.name, 'warning': self.warning_parsed, 'critical': self.critical_parsed, 'containers': self.container_IDs, 'value': self.value})

# Takes the threshold mapping, adjusts it so that thresholds are assigned to individual containers
def separate_checks(checks):
    ret = {}
    for key in checks.keys():
        ret.update(checks[key].to_individual_containers())

    return ret

def get_threshold_maps(warning_in, critical_in, attrs):
    check_data_map = {}
    warning_list = warning_in.split(',')
    critical_list = critical_in.split(',')
    if len(warning_list) == 1:
        warning_list *= len(attrs)
    if len(critical_list) == 1:
        critical_list *= len(attrs)

    for triplet in zip(attrs.keys(), warning_list, critical_list):
        check_data_map[triplet[0]] = CheckData(triplet[0], triplet[1], triplet[2], attrs[triplet[0]]);

    if len(attrs.keys()) != len(check_data_map.keys()):
        nagios_exit("At least one attribute does not have a a warning/critical threshold. Make sure thresholds are specified for each of these: %s" % attrs.keys(), check_status.UNKNOWN)

    return check_data_map

# Takes a standard nagios threshold, like @10:20, and 
# turns it into a 3-tuple (low, high, inclusive), like '(10, 20, true)
def threshold_string_to_tuple(threshold_string):
    if options.debug: print "hit " + "threshold_string_to_tuple"
    # Default values if not set
    low = 0
    high = float('inf') # ok even if we use integers otherwise
    inclusive = False

    if not threshold_string:
        threshold_string = "~:"
    
    if threshold_string[0] == "@":
        inclusive = True 
        threshold_string = threshold_string[1:]

    threshold_list = threshold_string.split(":")

    length = len(threshold_list)
    if length < 1 or length > 2:
        nagios_exit("Thresholds are composed of 1-2 arguments.", check_status.UNKNOWN)
    elif length == 1:
        try:
            high = float(threshold_list[0])
        except ValueError:
            nagios_exit(str(threshold_list[0]) + " could not be converted to a number", check_status.UNKNOWN)
    elif length == 2:
        if not threshold_list[0]:
            threshold_list[0] = "0"
        if (threshold_list[0] == "~" or threshold_list[0] == expanduser("~")):
            threshold_list[0] = "-inf"
        if not threshold_list[1]:
            threshold_list[1] = 'inf'
        try:
            low = float(threshold_list[0])
            high = float(threshold_list[1])
        except ValueError:
            nagios_exit("One of " + str(threshold_list) + " could not be converted to a number", check_status.UNKNOWN)
    if low > high:
        nagios_exit("The threshold minimum " + str(low) + " must be less than the maximum " + str(high), check_status.UNKNOWN)
    return low, high, inclusive

# checks the list of values against the threshold object returned by get_thresholds
def check_all_values_against_thresholds(check_data):
    if options.debug: print "hit " + "check_all_values_against_thresholds"
    highest_value = check_status.OK
    for key in check_data.keys():
        return_code = check_against_thresholds(check_data[key].value, check_data[key].warning_parsed, check_data[key].critical_parsed)
        check_data[key].setRC(return_code)
        if highest_value < return_code:
            highest_value = return_code
    return highest_value

def check_against_thresholds(value, warning_tuple, critical_tuple):
    if options.debug: print "hit " + "check_against_thresholds"
    crit = check_against_threshold(value, critical_tuple)
    if crit:
        return check_status.CRITICAL
    warn = check_against_threshold(value, warning_tuple)
    if warn:
        return check_status.WARNING
    return check_status.OK

def check_against_threshold(value, threshold_tuple):
    if options.debug: print "hit " + "check_against_threshold"
    if threshold_tuple[2]:
        if value < threshold_tuple[0] or value > threshold_tuple[1]:
            return False
        else:
            return True
    else:
        if value < threshold_tuple[0] or value > threshold_tuple[1]:
            return True
        else:
            return False

def make_perfdata(check_dict, uom, perf_min, perf_max):
    full_string = " | "
    for k, x in check_dict.iteritems():
        temp_string = "%s=%s%s;%s;%s;%s;%s" % (
            x.name, x.value, uom, x.warning_text, x.critical_text, 
            perf_min, perf_max)
        full_string += temp_string.rstrip(";") + " "
    return full_string

def make_userdata(labels, values):
    if options.debug: print "hit " + "make_userdata"
    full_string = ""
    for i, _ in enumerate(labels):
        full_string += "%s returned %s" % (labels[i], values[i])
    return full_string

def code_to_status(return_code):
    if return_code < check_status.OK or return_code > check_status.UNKNOWN:
        return_code = check_status.UNKNOWN
    words = ["OK", "WARNING", "CRITICAL", "UNKNOWN"]
    return words[return_code]

# Takes a list of unicode strings and returns an equivalent list of python strings.
def unicode_encode_list(l):
    if not isinstance(l, list):
        return l
    returned_list = []
    for uni in l:
        returned_list.append(uni.encode('UTF8'))
    return returned_list
# START API HELPERS

# Takes the list of endpoints and form values, communicates with the docker socket.
# Returns a JSON object
def talk_to_docker(endpoints_list, form_values_list, crash_on_fail=True):
    if options.debug: print "hit " + "talk_to_docker"

    # Construct the full URL
    endpoints = "/".join(endpoints_list)
    form_values = "?"
    for v in form_values_list:
        form_values += "&" + v
    form_values = urllib.quote_plus(form_values, "/}{=:&?")
    full_url = options.host + endpoints + form_values 

    # Talk to Docker
    cmd = "curl %s '%s' -g -f %s %s %s" % (options.socket, full_url, options.cert, options.key, options.cacert)
    #cmd = "curl " + options.socket + " '" + full_url + "' -g -f " + \
    #      options.cert + " " + options.key + " " + options.cacert
    if options.debug: print str(cmd)
    args = shlex.split(cmd.encode('ascii'))
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return_string, err = p.communicate()
    if not return_string:
        if options.debug:
            print "ERR " + err
            print "STDOUT " + return_string  
        if crash_on_fail:
            nagios_exit("cURL call failed", check_status.UNKNOWN, "", "Stderr: " + err)
        else:
            return None

    # Convert to JSON
    return_object = json.loads(return_string)
    return return_object # Note: all strings are unicode!

def get_container_IDs_from_names(names):
    if options.debug: print "hit " + "get_container_IDs_from_names"
    if isinstance(names, basestring):
        names = [names]
    endpoints_list = ['containers', 'json']
    ID_list = []
    for name in names:
        form_values_list = ['filters={"name":["' + name + '"]}', 'all=true']
        candidates = talk_to_docker(endpoints_list, form_values_list)
        for c in candidates:
            for name_ in c['Names']:
                if name_ == name or name_ == "/" + name:
                    ID_list.append(c['Id'])
                    break
    return ID_list

def get_container_IDs_from_network_IDs(network_IDs):
    if options.debug: print "hit " + "get_container_IDs_from_network_IDs"
    if isinstance(network_IDs, basestring):
        network_IDs = [network_IDs]
    form_values_list = []
    container_IDs = []
    for ID in network_IDs:
        endpoints_list = ['networks', ID]
        network = talk_to_docker(endpoints_list, form_values_list)
        container_list = network["Containers"]
        for container_ID, data in container_list:
            container_IDs.append(container_ID)
    return container_IDs

def get_container_IDs_from_network_names(names):
    if options.debug: print "hit " + "get_container_IDs_from_network_names"
    if isinstance(names, basestring):
        names = [names]
    endpoints_list = 'networks'
    container_IDs = []
    for name in names:
        form_values_list = ['filters={"name":["' + name + '"]}', 'all=1']
        json_object = talk_to_docker(endpoints_list, form_values_list)
        ID = ""
        for network in json_object:
            if network['Name'] == name or network['Name'] == ("/" + name):
                ID = network['Id']
                break;
        if ID:
            container_IDs += get_container_IDs_from_network_IDs(ID)
    return container_IDs

# Takes the container json object from talk_to_docker(), and the name of the image we're looking for
# returns a list of container IDs
def filter_containers_by_image_name(containers, image_name):
    return [container for container in containers if container['Image'] == image_name]

def images_list_to_dict(images_list):
    if options.debug: print "hit images_list_to_dict"
    ret_dict = {}
    containers = get_all_containers()
    for image in images_list:
        filtered_containers = filter_containers_by_image_name(containers, image)
        ret_dict[image] = [container['Id'] for container in filtered_containers]
    return ret_dict


def get_all_containers():
    if options.debug: print "hit get_all_containers"
    endpoints_list = ["containers", "json"]
    form_values_list = ["all=1"]
    all_containers = talk_to_docker(endpoints_list, form_values_list)
    return all_containers

def get_all_container_IDs():
    if options.debug: print "hit " + "get_all_container_IDs"
    all_containers = get_all_containers()
    ret = []
    for container in all_containers:
        ret.append(container['Id'])
    return ret

# selection is dictionary of lists. keys are passed in via -C/-N/-I, list elements are container IDs
# returns a list of container IDs, none of which are repeated
def get_container_IDs(selection):
    if options.debug: print "hit " + "get_container_IDs"
    IDs = []
    for alias in selection:
        IDs += selection[alias].container_IDs
    IDs = list(set(IDs))
    return IDs

# returns a dictionary of selected container aliases associated to lists of container IDs
# like {"some_name" : ["2dc17c606ce16d6b19cb13ca2e86286817d1945a80bbfe173acd3f203fb84b16"]}
# list form because names aren't guaranteed to be unique
def containers_list_to_dict(container_list):
    if options.debug: print "hit " + "containers_list_to_dict"
    ret_dict = {}
    for container in container_list:
        ret_dict[container] = []
        json_object = is_docker_container_ID(container)
        if json_object:
            ret_dict[container].append(json_object['Id'])
        else:
            json_object = is_docker_container_name(container)
            if json_object:
                ret_dict[container] += get_container_IDs_from_names(container)
    return ret_dict

# returns a dictionary of network names/ids associated with a list of container IDs.
def networks_list_to_dict(network_list):
    if options.debug: print "hit " + "networks_list_to_dict"
    ret_dict = {}
    for network in network_list:
        ret_dict[network] = []
        if is_docker_network_ID(network):
            ret_dict[network] += get_container_IDs_from_network_IDs(network)
        elif is_docker_network_name(network):
            ret_dict[network] += get_container_IDs_from_network_names(network)
    return ret_dict

def is_docker_network_ID(value):
    if options.debug: print "hit " + "is_docker_network_ID"
    endpoints_list = ['networks']
    form_values_list = ['filters={"id":["' + value + '"]}', 'all=1']
    json_object = talk_to_docker(endpoints_list, form_values_list)
    if json_object:
        return json_object[0]
    return False

def is_docker_container_ID(value):
    if options.debug: print "hit " + "is_docker_container_ID"
    endpoints_list = ['containers', 'json']
    form_values_list = ['filters={"id":["' + value + '"]}', 'all=1']
    json_object = talk_to_docker(endpoints_list, form_values_list)
    if json_object:
        return json_object[0]
    return False

def is_docker_container_name(value):
    if options.debug: print "hit is_docker_container_name"
    endpoints_list = ['containers', 'json']
    form_values_list = ['filters={"name":["' + value + '"]}', 'all=true']
    json_object = talk_to_docker(endpoints_list, form_values_list)
    if json_object:
        return json_object[0]
    return None

def is_docker_network_name(value):
    if options.debug: print "hit is_docker_network_name"
    endpoints_list = ['networks']
    container_IDs = []
    form_values_list = ['filters={"name":["' + value + '"]}', 'all=1']
    json_object = talk_to_docker(endpoints_list, form_values_list)
    if json_object:
        return json_object[0]
    return None

#END API HELPERS

#START CHECK BLOCK

def check_containers_exist(ID_list):
    if options.debug: print "hit " + "check_containers_exist"
    missing_IDs = []
    endpoints_list = ["containers", "json"]
    form_values_list = ["all=true"]
    values = talk_to_docker(endpoints_list, form_values_list)
    counter = 0
    for ID in ID_list:
        exists = False
        for v in values:
            if(v["Id"] == ID):
                exists = True
        if not exists:
            missing_IDs.append(ID)
        else:
            counter += 1
    out = "%d containers found" % (counter)
    if missing_IDs and options.list_bad_containers:
        out += (". No containers found with IDs %s" % (unicode_encode_list(missing_IDs)))
    return (out, counter)

def check_containers_running(ID_list):
    if options.debug: print "hit " + "check_containers_running"

    endpoints_list = ["containers","json"]
    form_values_list = ['all=true']
    json_object = talk_to_docker(endpoints_list, form_values_list)

    not_running = []
    running = []
    for ID in ID_list:
        is_running = False
        for container in json_object:
            if ID == container["Id"]:
                # 'Running' *may* have first letter capitalized
                if "unning" in container["State"]:
                    running.append(container["Names"][0])
                else:
                    not_running.append(container["Names"][0])
                break
        else:
            not_running.append(ID)

    running_count = len(running)
    not_running_count = len(not_running)

    if options.percentage:
        denominator = running_count + not_running_count
        counter = running_count/float(denominator) * 100
        out = "%f%% of containers (%d/%d) running" % (counter, running_count, denominator)
    else:
        counter = running_count
        out = "%d running" % (len(running))
        if not_running:
            out += ", %d not running" % (len(not_running))
            if options.list_bad_containers:
                out += ", containers not running: %s" % (unicode_encode_list(not_running))
    return (out, counter)

def check_containers_healthy(ID_list):
    if options.debug: print "hit " + "check_containers_healthy"
    endpoints_list = ["containers","json"]

    form_values_list = ['filters={"health":["unhealthy"]}']
    json_object_unhealthy = talk_to_docker(endpoints_list, form_values_list)

    if options.debug: print "json_object_unhealthy " + str(json_object_unhealthy)

    form_values_list = ['filters={"health":["healthy"]}']
    json_object_healthy = talk_to_docker(endpoints_list, form_values_list)

    if options.debug: print "json_object_healthy " + str(json_object_healthy)

    unhealthy = []
    healthy = []
    no_check = []
    for ID in ID_list:

        missing_healthy = False
        for container in json_object_healthy:
            if ID == container['Id']:
                healthy.append(container['Names'][0])
                break
        else:
            missing_healthy = True

        missing_unhealthy = False
        for container in json_object_unhealthy:
            if ID == container['Id']:
                unhealthy.append(container['Names'][0])
                break
        else:
            missing_unhealthy = True

        if missing_healthy and missing_unhealthy:
            no_check.append(ID) # Technically includes "starting".

    if options.debug:
        print "healthy " + str(healthy)
        print "unhealthy " + str(unhealthy)
        print "no_check " + str(no_check)

    if options.ignore_no_healthcheck:
        no_check = []

    total = len(healthy) + len(unhealthy) + len(no_check)
    out = "%d containers monitored" % (total)
    if not total:
        counter = 0
        return (out, counter)

    valid_count = len(unhealthy) if options.count_unhealthy_containers else len(healthy)
    if options.missing_healthcheck_is_counted:
        valid_count += len(no_check)

    if options.percentage:
        counter = valid_count/float(total) * 100
        out = "%f%% of containers (%d/%d) healthy" % (counter, valid_count, total)
    else:
        if healthy:
            out += ", %d healthy" % (len(healthy))
        if unhealthy:
            out += ", %d unhealthy" % (len(unhealthy))
            if options.list_bad_containers:
                out += ", unhealthy containers: %s" % (unicode_encode_list(unhealthy))
        if no_check:
            out += ", %d have no health check" % (len(no_check))
            if options.list_bad_containers and (not options.missing_healthcheck_is_counted) and (not options.ignore_no_healthcheck):
                out += ", containers with no healthcheck: %s" % (unicode_encode_list(no_check))
        counter = valid_count
    return (out, counter)


def check_containers_CPU(ID_list):
    if options.debug: print "hit " + "check_containers_CPU"
    form_values_list = ['stream=false']
    usage_dict = {}
    total_usage = 0
    for ID in ID_list:
        endpoints_list = ["containers", ID, "stats"]
        json_object = talk_to_docker(endpoints_list, form_values_list)
        if 'system_cpu_usage' in json_object['cpu_stats'].keys() and 'system_cpu_usage' in json_object['precpu_stats'].keys():
            container_CPU_delta = json_object['cpu_stats']['cpu_usage']['total_usage'] - json_object['precpu_stats']['cpu_usage']['total_usage']
            system_CPU_delta = json_object['cpu_stats']['system_cpu_usage'] - json_object['precpu_stats']['system_cpu_usage']
            # These values are usually quite large (~10^15 for the numbers we're subtracting)
            if system_CPU_delta == 0:
                system_CPU_delta = 1
        else:
            # Container is likely turned off
            container_CPU_delta = 0
            system_CPU_delta = 1
        percent_usage = container_CPU_delta/float(system_CPU_delta) * 100
        total_usage += percent_usage
        usage_dict[ID] = percent_usage
    return ("", [total_usage, usage_dict])

def check_containers_memory(ID_list):
    if options.debug: print "hit " + "check_containers_memory"
    if options.debug: print "ID_list is " + str(ID_list)
    form_values_list = ['stream=false']
    usage_dict = {}
    total_usage = 0
    for ID in ID_list:
        endpoints_list = ["containers", ID, "stats"]
        json_object = talk_to_docker(endpoints_list, form_values_list)
        if 'usage' in json_object['memory_stats'].keys() and 'limit' in json_object['memory_stats'].keys():
            mem_usage = json_object['memory_stats']['usage']
            mem_limit = json_object['memory_stats']['limit']
        else:
            # Container is likely turned off
            mem_usage = 0
            mem_limit = 1
        if options.percentage:
            percent_usage = mem_usage/float(mem_limit) * 100
            usage_dict[ID] = percent_usage
            total_usage += percent_usage
        else:
            usage_dict[ID] = mem_usage
            total_usage += mem_usage
    return ("", [total_usage, usage_dict])

#END CHECK BLOCK

#START PROCESS BLOCK

#Process counter: for now, just takes a single number - The count.
# returns perfdata for count=#;w;c;min;max and the correct exit code
def process_counter(checks, value):
    if options.debug: print "hit " + "process_counter"
    if type(value) is int or type(value) is float:
        uom = ""
        label = "count"
        if options.percentage:
            uom = "%"
            label = "percentage"

        for key in checks:
            checks[key].setValue(value)
        perfdata = make_perfdata(checks, uom, options.perfdata_min, options.perfdata_max)
        return_code = check_all_values_against_thresholds(checks)
        return (perfdata, return_code)
    return ("This line of code should never be reached. Please contact the plugin maintainer.", check_status.UNKNOWN)

# Expects a dictionary mapping IDs to usage values.
def process_usage(checks, value):
    if options.debug: print "hit " + "process_usage"
    if not (type(value[1]) is dict):
        nagios_exit("Data in wrong format", check_status.UNKNOWN)
    if (not options.all) and \
       (not options.containers) and \
       (not options.networks) and \
       (not options.images):
        nagios_exit("All/containers/networks/images not set. "
            "This line should never be reached. "
            "Please contact the plugin maintainer", check_status.UNKNOWN)
    global unit_dict
    container_id_to_usage = value[1]
    total_usage = value[0]

    if options.debug:
        print "container_id_to_usage is"
        print container_id_to_usage

    # Initialize the values of certain labels, values, units of measure.
    if options.total_usage or options.all:
        checks['total_usage'].setValue(total_usage)
    if options.total_average:
        if options.all or options.images:
            total_average = total_usage / float(len(list(container_id_to_usage.keys())))
        else:
            total_average = total_usage / float(max([1,len(checks)]))
        checks['average_usage'].setValue(total_average)

    # Set Unit of Measure
    uom = "B"
    if options.memory_unit:
        uom = options.memory_unit
    if options.percentage:
        uom = '%'

    # Get additional values
    for check in checks.keys():
        alias_value = checks[check].value
        alias_counter = 0
        for ID in checks[check].container_IDs:
            if options.networks_use_avg:
                alias_counter += 1
            alias_value += container_id_to_usage[ID]
        if options.networks_use_avg and options.networks:
            alias_value = alias_value/float(alias_counter)
        checks[check].setValue(alias_value)
        if uom:
            checks[check].scale(uom)

    #Make perfdata
    short_checks = dict((i, checks[i]) for i in checks if i in ['total_usage', 'average_usage'])
    long_checks = dict((i, checks[i]) for i in checks if i not in ['total_usage', 'average_usage'])

    perfdata_short = make_perfdata(short_checks, uom, options.perfdata_min, options.perfdata_max)
    perfdata_long = make_perfdata(long_checks, uom, options.perfdata_min, options.perfdata_max)

    # Check values, generate output
    output_short = ""
    output_long = ""
    if options.no_individual_checks:
        checks = short_checks
    return_code = check_all_values_against_thresholds(checks)

    if short_checks:
        for k, v in short_checks.iteritems():
            output_short += "%s returned %s (value %s%s), " % (
                v.name, 
                code_to_status(v.RC), 
                v.value,
                uom)
    if not options.no_individual_checks:
        for k, v in long_checks.iteritems():
            output_long += "%s returned %s (value %s%s) \n" % (
                v.name, 
                code_to_status(v.RC), 
                v.value,
                uom)
    output_final = output_short + perfdata_short 
    if not options.no_individual_checks and output_long:
        output_final += "\n" + output_long + perfdata_long

    return output_final, return_code

#END PROCESS BLOCK

#START MAIN AND SWITCHES

def do_check(ID_list):
    if options.debug: print "hit " + "do_check"
    global valid_checks
    # switch on check type.
    (out,value) = valid_checks[options.check_type][0](ID_list)
    return (out,value)

def process_value(checks, values):
    if options.debug: print "hit " + "process_value"
    global valid_checks
    (perfdata, exit) = valid_checks[options.check_type][1](checks, values)
    return (perfdata, exit)

def main():
    options = get_options()
    checks = choose_checks(options)
    ID_list = get_all_container_IDs() if options.all else get_container_IDs(checks)
    (out, values) = do_check(ID_list) # Gives plugin output and a number/dict{str:int}
    (perfdata, exit) = process_value(checks, values) # Gives a complete perfdata string and an exit code
    nagios_exit(out, exit, perfdata)


valid_checks =  { "containers_exist"    : (check_containers_exist, process_counter),
                  "containers_running"  : (check_containers_running, process_counter),
                  "containers_healthy"  : (check_containers_healthy, process_counter),
                  "containers_cpu"      : (check_containers_CPU, process_usage),
                  "containers_memory"   : (check_containers_memory, process_usage),
}


unit_dict = { ""   : 1,
              "%"  : 1,
              "B"  : 1,
              "KiB": 1024,
              "MiB": 1048576,
              "GiB": 1073741824,
              "b"  : 1, # not actually bits, just lower-case version of the units above
              "kib": 1024,
              "mib": 1048576,
              "gib": 1073741824 }

#END MAIN AND SWITCHES

if __name__ == "__main__":
    _ = main()
    nagios_exit("Plugin escaped the main function. Please report this error to the plugin maintainer.", check_status.UNKNOWN)
    sys.exit(check_status.UNKNOWN)
