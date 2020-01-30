###############################################################################
#
# Script:       add-security-profile-group.py
#
# Author:       Chris Goodwin <chrisgoodwins@gmail.com>
#
# Description:  This script presents the user with the ability to apply a
#               security profile group to selected policies, or all policies
#               within a device group. Once the user authenticates to Panorama,
#               the user is presented with a list of device groups. Then, the
#               user chooses from a list of security profile groups contained
#               within the selected device group. Next, the user specifies
#               which security rulebase to apply the profile. The user is
#               given the option of displaying the rules before doing so.
#
# Usage:        add-security-profile-group.py
#
# Requirements: requests
#
# Python:       Version 3
#
###############################################################################
###############################################################################


import getpass
import re
import time
from xml.etree import ElementTree as ET
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    raise ValueError('requests support not available, please install module')


# Prompts the user to enter an address, then checks it's validity
def getfwipfqdn():
    while True:
        fwipraw = input("\nPlease enter Panorama IP or FQDN: ")
        ipr = re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", fwipraw)
        fqdnr = re.match(r"(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)", fwipraw)
        if ipr:
            break
        elif fqdnr:
            break
        else:
            print("\nThere was something wrong with your entry. Please try again...\n")
    return fwipraw


# Prompts the user to enter a username and password
def getCreds():
    while True:
        username = input("Please enter your user name: ")
        usernamer = re.match(r"^[\w-]{3,24}$", username)
        if usernamer:
            password = getpass.getpass("Please enter your password: ")
            break
        else:
            print("\nThere was something wrong with your entry. Please try again...\n")
    return username, password


# Retrieves the user's api key
def getkey(fwip):
    while True:
        try:
            fwipgetkey = fwip
            username, password = getCreds()
            keycall = "https://%s/api/?type=keygen&user=%s&password=%s" % (fwipgetkey, username, password)
            r = requests.get(keycall, verify=False)
            tree = ET.fromstring(r.text)
            if tree.get('status') == "success":
                apikey = tree[0][0].text
                break
            else:
                print("\nYou have entered an incorrect username or password. Please try again...\n")
        except requests.exceptions.ConnectionError:
            print("\nThere was a problem connecting to the firewall. Please check the address and try again...\n")
            exit()
    return apikey


# Presents the user with a choice of device-groups
def getDG(baseurl, mainkey):
    dgXmlUrl = "/api/?type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/device-group&key="
    dgFullUrl = (baseurl + dgXmlUrl + mainkey)
    r = requests.get(dgFullUrl, verify=False)
    dgfwTree = ET.fromstring(r.text)
    dgList = []
    for entry in dgfwTree.findall('./result/device-group/entry'):
        dgList.append(entry.get('name'))
    while True:
        try:
            print('\n\nHere\'s a list of device groups found in Panorama...\n')
            i = 1
            for dgName in dgList:
                if i < 10:
                    print('%s)  %s' % (i, dgName))
                else:
                    print('%s) %s' % (i, dgName))
                i += 1
            dgChoice = int(input('\nChoose a number for the device-group\n\nAnswer: '))
            reportDG = dgList[dgChoice - 1]
            break
        except:
            print("\n\nThat's not a number in the list, try again...\n")
            time.sleep(1)
    return reportDG


# Checks for shared and parent device groups, and returns a list of them
def getParentDGs(devGroup, baseurl, mainkey):
    pDGs = []
    dgHierarchyURL = baseurl + '/api/?type=op&cmd=<show><dg-hierarchy></dg-hierarchy></show>&key=' + mainkey
    r = requests.get(dgHierarchyURL, verify=False)
    dgHierarychyTree = ET.fromstring(r.text)
    for dg in dgHierarychyTree.findall(".//*/[@name='%s']..." % (devGroup)):
        pDGs.append(dg.get('name'))
    sharedSecGroupProfURL = baseurl + '/api/?type=config&action=get&xpath=/config/shared/profile-group&key=' + mainkey
    r = requests.get(sharedSecGroupProfURL, verify=False)
    sharedSecGroupProfTree = ET.fromstring(r.text)
    if sharedSecGroupProfTree.find('./result/profiles/entry') is not None:
        pDGs.append('shared')
    return pDGs


# Presents the user with a choice of security profile groups for the chosen device-group
def getSecGroupProfile(devGroup, baseurl, mainkey):
    allDGs = getParentDGs(devGroup, baseurl, mainkey)
    allDGs.append(devGroup)
    secGroupProfileList = []
    for dg in allDGs:
        if dg == 'shared':
            secGroupProfileXmlUrl = "/api/?type=config&action=get&xpath=/config/shared/profile-group&key="
        else:
            secGroupProfileXmlUrl = "/api/?type=config&action=get&xpath=/config/devices/entry/device-group/entry[@name='%s']/profile-group&key=" % (dg)
        secGroupProfileFullUrl = (baseurl + secGroupProfileXmlUrl + mainkey)
        r = requests.get(secGroupProfileFullUrl, verify=False)
        secGroupProfileFwTree = ET.fromstring(r.text)
        for entry in secGroupProfileFwTree.findall('./result/profile-group/entry'):
            secGroupProfileList.append(entry.get('name'))
    if secGroupProfileList != []:
        while True:
            try:
                print('\n\n\nHere\'s a list of security profile groups found for the %s device group...\n' % (devGroup))
                i = 1
                for secGroupProfileName in secGroupProfileList:
                    print('%s) %s' % (i, secGroupProfileName))
                    i += 1
                secGroupProfileChoice = int(input('\nChoose a number for the security profile group\n\nAnswer: '))
                reportSecGroupProfile = secGroupProfileList[secGroupProfileChoice - 1]
                break
            except:
                print("\n\nThat's not a number in the list, try again...\n")
    else:
        print('\n\nThere were no security profile groups found for the %s device group, please choose another device group...\n' % (devGroup))
        devGroup = getDG(baseurl, mainkey)
    return reportSecGroupProfile


# Returns a security rulebase and list of security policies for the chosen device group
def getPolicies(devGroup, baseurl, mainkey):
    while True:
        try:
            time.sleep(1)
            rulebase_answer = int(input('\n\n\nWhich rulebase would you like to modify policies?\n\n1) Pre-Rulebase\n2) Post-Rulebase\n\nAnswer: '))
            if rulebase_answer == 1:
                rulebase = 'pre-rulebase'
                break
            elif rulebase_answer == 2:
                rulebase = 'post-rulebase'
                break
            else:
                print("\n\nThat wasn't one of the options, try again...\n\n")
        except:
            print("\n\nThat's not a number, try again...\n")
    secPoliciesXmlUrl = "/api/?type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/%s/security/rules&key=" % (devGroup, rulebase)
    secPoliciesFullUrl = (baseurl + secPoliciesXmlUrl + mainkey)
    r = requests.get(secPoliciesFullUrl, verify=False)
    secPoliciesFwTree = ET.fromstring(r.text)
    secPolicyList_All = []
    for entry in secPoliciesFwTree.findall('./result/rules/entry'):
        secPolicyList_All.append(entry.get('name'))
    secPolicyListLength = len(secPolicyList_All)
    while True:
        policyID = 1
        if secPolicyList_All == []:
            secPolicyList = []
            break
        time.sleep(1)
        print('\n\nThe ' + rulebase + ' for the ' + devGroup + ' device group contains ' + str(secPolicyListLength) + ' security policies\n')
        secPolicyList_answer = input("Type 'all' to apply the the security profile groups to all security policies,\nor hit enter to display the policies in order to select which to apply the profile\n\nAnswer: ")
        if secPolicyList_answer.lower() == 'all':
            secPolicyList = secPolicyList_All
            break
        elif secPolicyList_answer == '':
            print('')
            time.sleep(1)
            for secPolicy in secPolicyList_All:
                print(str(policyID) + ') ' + secPolicy)
                policyID += 1
            run = True
            while run:
                check = True
                selectPolicies = input('\n\nChoose from the list above by selecting the number.\nYou can select multiple policies by separating by comma, and/or by adding ranges.\nWhite space can be used, but will be stripped out when parsed.\nExample --> 19,42, 119-135,200-465, 477,687 - 4242\n\n\nAnswer: ')
                selectPolicies_r = re.match(r"^(((\d{1,5})|(\d{1,5}\s*-\s*\d{1,5}))(\s*,\s*((\d{1,5}\s*)|(\d{1,5}\s*-\s*\d{1,5})))*)$", selectPolicies)
                if selectPolicies_r:
                    pass
                else:
                    time.sleep(1)
                    print("\nYour entry wasn't in the proper format. Please enter either single entries or ranges separated by commas,\nor a combination of both. White space can be used, but will be stripped out when parsed.")
                    check = False
                while True and check is True:
                    secPolicyList_Indexes = re.sub(r'\s+', '', selectPolicies).split(',')
                    secPolicyList_Indexes_ranges = []
                    rangePattern = re.compile(r'-')
                    for i in secPolicyList_Indexes[:]:
                        if rangePattern.findall(i):
                            secPolicyList_Indexes_ranges.append(i)
                            secPolicyList_Indexes.remove(i)
                    secPolicyList_Indexes = list(map(int, secPolicyList_Indexes))
                    rangeCheck = True
                    for i in secPolicyList_Indexes_ranges:
                        x = list(map(int, i.split('-')))
                        if x[0] > x[1]:
                            rangeCheck = False
                            badRange = str(x[0]) + '-' + str(x[1])
                            break
                        y = range(x[0], x[1] + 1)
                        for z in y:
                            secPolicyList_Indexes.append(z)
                    if rangeCheck:
                        secPolicyList_Indexes.sort()
                        secPolicyList_Indexes = list(set(secPolicyList_Indexes[:]))
                        secPolicyList_Indexes_Length = len(secPolicyList_Indexes)
                        print()
                        if secPolicyList_Indexes[secPolicyList_Indexes_Length - 1] > secPolicyListLength:
                            time.sleep(1)
                            print("\n\nYour entry was found to have a number that was out of range for the number of policies contained within the device group's rulebase.\nThere are a total of " + str(secPolicyListLength) + " policies in the rulebase. Make sure your entries fall within the proper range.")
                            break
                        else:
                            secPolicyList = []
                            for index in secPolicyList_Indexes:
                                secPolicyList.append(secPolicyList_All[index - 1])
                            print('\n\nHere are the policies that you have chosen:\n')
                            count = 0
                            for x in secPolicyList:
                                print(str(secPolicyList_Indexes[count]) + ') ' + x)
                                count += 1
                            run = False
                            break
                    else:
                        time.sleep(1)
                        print('\n\nYou entered a range incorrectly (%s), please check your list and try again.' % badRange)
                        break
            break
        else:
            print("\n\nThat wasn't one of the options, try again...\n\n")
    return rulebase, secPolicyList


# Applies the security profile group to the selected rulebase and device group
def main():
    fwip = getfwipfqdn()
    mainkey = getkey(fwip)
    baseurl = 'https://' + fwip
    run = False
    while True:
        devGroup = getDG(baseurl, mainkey)
        secGroupProfile = getSecGroupProfile(devGroup, baseurl, mainkey)
        rulebaseType, secPolicies = getPolicies(devGroup, baseurl, mainkey)
        if secPolicies == []:
            time.sleep(1)
            print('\n\nThere are no security policies present in the %s for the %s device group, please choose another device group and/or rulebase...\n' % (rulebaseType, devGroup))
        else:
            run = True
        while run:
            time.sleep(1)
            applyProfile_answer = input('\n\nWould you like to go ahead with applying the %s security profile group\nto the policies specified above for the %s device group? [y/n]\n\nAnswer: ' % (secGroupProfile, devGroup))
            if applyProfile_answer == 'y' or applyProfile_answer == 'Y':
                xmlElement = ''
                count = 0
                for secPolicy in secPolicies:
                    xmlElement = xmlElement + "<entry name='%s'><profile-setting><group><member>%s</member></group></profile-setting></entry>" % (secPolicy, secGroupProfile)
                    count += 1
                applyProfilesURL = baseurl + "/api/?type=config&action=set&xpath=/config/devices/entry/device-group/entry[@name='" + devGroup + "']/" + rulebaseType + "/security/rules&element=" + xmlElement + '&key=' + mainkey
                r = requests.get(applyProfilesURL, verify=False)
                applyProfilesFwTree = ET.fromstring(r.text)
                if applyProfilesFwTree.get('status') == 'success':
                    time.sleep(1)
                    print("\n\nCongrats! The '%s' security profile group was applied to the %s specified policies in the %s device group\n\n\n\nHave a great day!!!\n\n" % (secGroupProfile, count, devGroup))
                    exit()
                else:
                    print('\n\nThere was something wrong with the API call that was sent to Panorama\nPlease check the API call below to troubleshoot the issue...\n\n%s' % (applyProfilesURL))
                    exit()
            elif applyProfile_answer == 'n' or applyProfile_answer == 'N':
                print("\n\nOk, let's back up then...\n")
                while True:
                    check = True
                    time.sleep(1)
                    change_answer = int(input("Which would you like to change?\n\n1) Device Group\n2) Security Profile Group\n3) Rulebase\n\nAnswer: "))
                    if change_answer == 1:
                        devGroup = getDG(baseurl, mainkey)
                        secGroupProfile = getSecGroupProfile(devGroup, baseurl, mainkey)
                        rulebaseType, secPolicies = getPolicies(devGroup, baseurl, mainkey)
                    elif change_answer == 2:
                        secGroupProfile = getSecGroupProfile(devGroup, baseurl, mainkey)
                    elif change_answer == 3:
                        rulebaseType, secPolicies = getPolicies(devGroup, baseurl, mainkey)
                    else:
                        print("\n\nThat wasn't one of the options, try again...\n\n")
                        check = False
                    if secPolicies == [] and check is True:
                        time.sleep(1)
                        print('\n\nThere are no security policies present in the %s for the %s device group, please choose another device group and/or rulebase...\n' % (rulebaseType, devGroup))
                        run = False
                        break
                    elif secPolicies != [] and check is True:
                        break
            else:
                print("\n\nThat wasn't one of the options, try again...\n\n")


if __name__ == '__main__':
    main()
