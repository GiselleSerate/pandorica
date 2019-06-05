import datetime
import json
import time

from flask import Flask
import requests
from logging.config import dictConfig

dictConfig({
    'version': 1,
    'formatters': {'default': {
        'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
    }},
    'handlers': {'wsgi': {
        'class': 'logging.StreamHandler',
        'stream': 'ext://flask.logging.wsgi_errors_stream',
        'formatter': 'default'
    }},
    'root': {
        'level': 'DEBUG',
        'handlers': ['wsgi']
    }
}) # TODO can you put this after config and get log level from config py? 

# Configuration
app = Flask(__name__)
app.config.from_object('config.DebugConfig')


def processTagList(tagObj):
    tagList = list()
    sample = tagObj['_source']

    # If we have tags associated with samples, extract them for each
    # sample and then get their meta-data
    if 'tag' in sample:
        app.logger.debug(f"Found tag(s) {sample['tag']} in sample")

        for tagName in sample['tag']:
            app.logger.debug(f"Processing tag {tagName}")

            tagData = processTag(tagName)
            tagList.append(tagData)
    else:
        tagData = "NULL"

    app.logger.debug(f"processTagList() returns: {tagList}")

    return tagList


def processTag(tagName):
    '''
    Method determines if we have a local tag info cache or we need to go to AF
    and gather the info.  Returns the data for manipulation by the calling
    method
    '''
    tagDoc = False
    updateDetails = False
    afApiKey = app.config['AUTOFOCUS_API_KEY']
    retStatusFail = f'Failed to get info for {tagName} - FAIL'
    now = datetime.datetime.now().replace(microsecond=0).isoformat(' ')
    timeLimit = (datetime.datetime.now() -
                 datetime.timedelta(days=app.config['DOMAIN_TAG_INFO_MAX_AGE']))
    tagGroupDict = [{"tag_group_name": "Undefined",
                     "description": "Tag has not been assigned to a group"}]

    app.logger.debug(f"Querying local cache for {tagName}")
    # import pdb
    # pdb.set_trace()
    try:
        tagDoc = TagDetailsDoc.get(id=tagName)
        
        
        # check age of doc and set to update the details
        if timeLimit > tagDoc.doc_updated:
            app.logger.debug(f"Last updated can't be older than {timeLimit} " +
                             f"but it is {tagDoc.doc_updated} and we need to " +
                             f"update cache")
            updateDetails = True
            updateType = "Updating"
        else:
            # If the tag groups are empty send back Undefined
            if not tagDoc.tag_groups or tagDoc.tag_groups == "":
                app.logger.debug(f"No tag group found, setting to undefined")
                tagDoc.tag_groups = tagGroupDict
            # else:
            #     tagDoc.tag_groups = afTagData['tag_groups']

            app.logger.debug(f"Last updated can't be older than {timeLimit} " +
                             f"and {tagDoc.doc_updated} isn't, will not update cache")


    except NotFoundError as nfe:
        app.logger.info(f"No local cache found for tag {tagName} - Creating")
        updateDetails = True
        updateType = "Creating"
        
        

    if updateDetails:
        afTagData = getTagInfo(tagName)
        # If we get the word 'message' in the return it means something went
        # wrong, so just return False
        if "message" not in afTagData:
            app.logger.debug(f"{updateType} doc for {tagName}")

            tagDoc = TagDetailsDoc(meta={'id': tagName}, name=tagName)
            tagDoc.tag = afTagData['tag']
            tagDoc.doc_updated = now
            tagDoc.type_of_doc = "tag-doc"
            tagDoc.processed = 1

            # If the tag groups are empty send back Undefined
            if not afTagData['tag_groups'] or afTagData['tag_groups'] == "":
                tagDoc.tag_groups = tagGroupDict
            else:
                tagDoc.tag_groups = afTagData['tag_groups']

            # Only set the doc_created attribute if we aren't updating
            if updateType == "Creating":
                tagDoc.doc_created = now

            app.logger.debug(f"tagDoc is {tagDoc.to_dict()} ")

            tagDoc.save()

            tagDoc = TagDetailsDoc.get(id=tagName)

        else:
            return False
    app.logger.debug(f"{tagDoc}")
    app.logger.debug(f"processTag() returns: " +
                     f"{tagDoc.tag['tag_name'],tagDoc.tag['public_tag_name']}" +
                     f"{tagDoc.tag['tag_class'],tagDoc.tag_groups[0]['tag_group_name']}," +
                     f"{tagDoc.tag['description']}")

    return (tagDoc.tag['tag_name'], tagDoc.tag['public_tag_name'],
            tagDoc.tag['tag_class'], tagDoc.tag_groups[0]['tag_group_name'],
            tagDoc.tag['description'])




def getDomainInfo(threatDomain):
    '''
    Method that uses user supplied api key (.panrc) and gets back a "cookie."
    Loops through timer (in minutes) and checks both the timer value and the
    maximum search result percentage and returns the gathered domain data when
    either of those values are triggered
    '''
    domainObj = list()
    domainObj.append(('2000-01-01T00:00:00', 'NA',
                      [('No Samples Returned for Domain',
                        'No Samples Returned for Domain',
                        'No Samples Returned for Domain',
                        'No Samples Returned for Domain',
                        'No Samples Returned for Domain')]))
    apiKey = app.config['AUTOFOCUS_API_KEY']
    searchURL = app.config["AUTOFOCUS_SEARCH_URL"]
    resultURL = app.config["AUTOFOCUS_RESULTS_URL"]
    lookupTimeout = app.config["AF_LOOKUP_TIMEOUT"]
    maxPercentage = app.config["AF_LOOKUP_MAX_PERCENTAGE"]
    resultData = {"apiKey": apiKey}
    headers = {"Content-Type": "application/json"}
    searchData = {"apiKey": apiKey,
                  "query": {
                      "operator": "all",
                      "children": [{
                          "field": "alias.domain",
                          "operator": "contains",
                          "value": threatDomain}]},
                  "size": 100,
                  "from": 0,
                  "sort": {"create_date": {"order": "desc"}},
                  "scope": "global",
                  "artifactSource": "af"}

    # Query AF and it returns a "cookie" that we use to view the resutls of the
    # search

    app.logger.debug(f'Gathering domain info for {threatDomain} (10 API-points)')
    queryResponse = requests.post(url=searchURL, headers=headers,
                                  data=json.dumps(searchData))
    app.logger.debug(f"Initial AF domain query returned {queryResponse.json()}")
    queryData = queryResponse.json()

    # If the response has a message in it, it most likely means we ran out of
    # AF points.
    if 'message' in queryData:
        if "Daily Bucket Exceeded" in queryData['message']:
            app.logger.warning(f"We have exceeded the daily allotment of points "
                             f"for AutoFocus - NOT going into hibernation mode.")
            # checkAfPoints(queryData['bucket_info'])
            # # The checkAfPoints will eventually return after the points reset.
            # # When they do, reurn the AF query so we don't lose it.
            # app.logger.debug(f'Gathering domain info for {threatDomain}')
            # queryResponse = requests.post(url=searchURL, headers=headers,
            #                               data=json.dumps(searchData))
            # app.logger.debug(f"Initial AF domain query returned "
            #                  f"{queryResponse.json()}")
            # queryData = queryResponse.json()
        elif "Minute Bucket Exceeded" in queryData['message']:
            app.logger.warning(f"We have exceeded the minute allotment of points "
                             f"for AutoFocus - NOT going into hibernation mode.")
            # checkAfPoints(queryData['bucket_info'])
            # # The checkAfPoints will eventually return after the points reset.
            # # When they do, reurn the AF query so we don't lose it.
            # app.logger.debug(f'Gathering domain info for {threatDomain}')
            # queryResponse = requests.post(url=searchURL, headers=headers,
            #                               data=json.dumps(searchData))
            # app.logger.debug(f"Initial AF domain query returned "
            #                  f"{queryResponse.json()}")
            # queryData = queryResponse.json()
        else:
            app.logger.error(f"Return from AutoFocus is in error: {queryData}")

    # Query should return an af_cookie or an error
    if 'af_cookie' in queryData:
        cookie = queryData['af_cookie']
        cookieURL = resultURL + cookie

        app.logger.debug(f"Cookie {cookie} returned for query of {threatDomain}")

        # Wait for the alloted time before querying AF for search results.  Do
        # check every minute anyway, in case the search completed as the cookie
        # is only valid for 2 minutes after it completes.
        for timer in range(lookupTimeout):
            time.sleep(61)
            cookieResults = requests.post(url=cookieURL, headers=headers,
                                          data=json.dumps(resultData))
            domainData = cookieResults.json()
            app.logger.debug(f"Checking cookie {cookie} (2 API-points)")
            if domainData['af_complete_percentage'] >= maxPercentage:
                break
            else:
                app.logger.info(f"Search completion " +
                                f"{domainData['af_complete_percentage']}% for " +
                                f"{threatDomain} at {timer+1} minute(s): " +
                                f"{domainData}")

        if domainData['total'] != 0:
            for hits in domainData['hits']:
                app.logger.debug(f"calling processTagList({hits})")
                tagList = processTagList(hits)
                # reset domainObj to empty then add the returned tagList
                domainObj = list()
                domainObj.append((hits['_source']['finish_date'],
                                  hits['_source']['filetype'],
                                  tagList))

        else:
            app.logger.info(f"No samples found for {threatDomain} in time "
                            f"allotted")


    else:
        app.logger.error(f"Unable to retrieve domain info from AutoFocus. "
                         f"The AF query returned {queryData}")

    app.logger.debug(f"getDomainInfo() returns: {domainObj}")

    return domainObj

getDomainInfo('www.ldlvchurch.com')