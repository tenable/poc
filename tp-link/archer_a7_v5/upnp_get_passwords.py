import upnpy
import sys
from defusedxml.ElementTree import fromstring
import requests

upnp = upnpy.UPnP()
devices = upnp.discover()

# search devices looking for TP-Link with DLNA
the_device = None
found = False
for dev in devices:
    desc = fromstring(dev.description)
    if desc:
        for child in desc:
            if child.tag.endswith('device'):
                for i in child:
                    if i.tag.endswith('modelDescription') and 'DLNA' in i.text:
                        print('Found the device!')
                        the_device = dev
                        found = True
                        break
            if found:
                break
    if found:
        break

if the_device is None:
    print("Couldn't find the TP-Link device.")
    sys.exit(1)

# ensure ContentDirectory service exists
if 'ContentDirectory' not in the_device.services:
    print("This device doesn't have the ContentDirectory service.")
    sys.exit(1)

# now we have the service
content_dir = the_device.services['ContentDirectory']

# ensure Browse action is defined
if 'Browse' not in content_dir.actions:
    print("No Browse action found.")
    sys.exit(1)

# initial browse to get the object id
response = content_dir.Browse(ObjectID='0', BrowseFlag='BrowseDirectChildren', Filter='*', StartingIndex=0, RequestedCount=5000, SortCriteria='')

if not response or 'Result' not in response:
    print("Error with response to initial browse...")
    sys.exit(1)

result = fromstring(response['Result']) # xml
if not result:
    print("Error parsing result")
    sys.exit(1)

new_object_id = None
for container in result.findall('{urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/}container'):
    for title in container.findall('{http://purl.org/dc/elements/1.1/}title'):
        if 'Browse Folders' in title.text:
            new_object_id = container.get('id')
            break

    if new_object_id:
        break

print("Now going to browse for object " + str(new_object_id))

response = content_dir.Browse(ObjectID=str(new_object_id), BrowseFlag='BrowseDirectChildren', Filter='*', StartingIndex=0, RequestedCount=5000, SortCriteria='')

if not response or 'Result' not in response:
    print("Error browsing...")
    sys.exit(1)


result = fromstring(response['Result'])

files = {}
for item in result.findall('{urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/}item'):
    title = item.find('{http://purl.org/dc/elements/1.1/}title')
    url = item.find('{urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/}res')
    files[title.text] = url.text


for fname, url in files.items():
    res = requests.get(url)
    print('\n-- ' + fname + ' (' + url + ')' + ":")
    print(res.text)

