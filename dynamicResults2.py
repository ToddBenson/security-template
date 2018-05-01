#! /usr/bin/python
from datadog import api
from datadog import initialize
from time import strftime
import urllib2, time, json
import os.path

# env code
apiKey = os.getenv('DATADOG_APIKEY')
appKey = os.getenv('DATADOG_APPKEY')

options = {
    'api_key': apiKey,
    'app_key': appKey
}

TIME = time.time()
# TIME = strftime("%m%d%Y", time.localtime())


def sendtodatadog(title, newtag, count):
    initialize(**options)
    # newtag = list()
    # newtag.append("application:" + id.lower())
    # newtag.append("risk:" + risklevel)
    # metric = 'security.' + title + ', points=(' + str(TIME) + ', ' + str(count) + '),tags=' + tag
    # print(metric='security.' + title, points=(TIME, float(count)), tags=newtag))
    print(title + "(" + str(TIME) + "," + str(count) + "," + str(newtag) + ")")
    print(api.Metric.send(metric='security.' + title, points=(TIME, float(count)), tags=newtag))


def create_tags(application, risklevel):
    newtag = list()
    newtag.append("application:" + application.lower())
    newtag.append("risk:" + risklevel)

    return newtag


def get_dynamic_vulns(id):
    filename = 'nightly-scan.json'
    if os.path.isfile(filename):
        with open(filename) as data_file:
            data = json.load(data_file)

            sendtodatadog('csaa.assessment.nightly_scan', create_tags(id, 'high'), data["High"])
            sendtodatadog('csaa.assessment.nightly_scan', create_tags(id, 'moderate'), data["Moderate"])
            sendtodatadog('csaa.assessment.nightly_scan', create_tags(id, 'low'), data["Low"])


def main():
    get_dynamic_vulns(os.getenv('APP'))
    initialize(**options)
    # api.Metric.send(metric='security.monitor.checks', points=0, tags=['status:qualys'])


if __name__ == "__main__":
    main()
