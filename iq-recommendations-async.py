#!/usr/bin/python3
# ----------------------------------------------------------------------------
# Python Dependencies
import time
import datetime
import json
import argparse
import asyncio
import aiohttp

from functools import lru_cache
# ----------------------------------------------------------------------------
t0 = time.time()
iq_url, iq_session = "", ""
api_calls = 0


class Cacheable:
    def __init__(self, co):
        self.co = co
        self.done = False
        self.result = None
        self.lock = asyncio.Lock()

    def __await__(self):
        with (yield from self.lock):
            if self.done:
                return self.result
            self.result = yield from self.co.__await__()
            self.done = True
            return self.result

def cacheable(f):
    def wrapped(*args, **kwargs):
        r = f(*args, **kwargs)
        return Cacheable(r)
    return wrapped

def getArguments():
    global iq_url, iq_session, iq_auth
    parser = argparse.ArgumentParser(description='Export Reporting Recommendations')
    parser.add_argument('-i', '--publicId', help='PublicId for the Application', required=True)
    parser.add_argument('-u', '--url', help='', default="http://localhost:8070", required=False)
    parser.add_argument('-a', '--auth', help='', default="admin:admin123", required=False)
    parser.add_argument('-s', '--stage', help='', default="build", required=False)
    parser.add_argument('-l', '--limiter', help='', default="0", required=False)
    args = vars(parser.parse_args())
    iq_url = args["url"]
    creds = args["auth"].split(":")
    iq_session = aiohttp.ClientSession()
    iq_auth = aiohttp.BasicAuth(creds[0], creds[1])
    return args
# -----------------------------------------------------------------------------
# GET api/v2/applications/{applicationPublicId}/reports/{scanId}/policy
# -----------------------------------------------------------------------------


async def main():
    args = getArguments()

    publicId = args["publicId"]
    stageId = args["stage"]
    limiter = int(args["limiter"])

    applicationId = await get_applicationId(publicId)
    reportId = await get_reportId(applicationId, stageId)
    report = await get_policy_violations(publicId, reportId)

    final = []
    total = report['counts']['totalComponentCount']

    if limiter > 0 and limiter <= total:
        print(f"Total components are {total}, but limiter is set to only {limiter}.")
        print("Pass in limiter of zero to get all results.")
        total = limiter

    for future_res in asyncio.as_completed([handle_component(report, index, total, applicationId, stageId)
                                            for index in range(total)]):
        result = await future_res
        final.append(result)

    await iq_session.close()
    t1 = int(time.time() - t0)
    # exclude time to write out the file from total
    dumps(final)
    print("Final results saved to -> results.json")
    print(f"Script took {t1} seconds to run with {api_calls} calls to the API.")

# -----------------------------------------------------------------------------


async def handle_component(report, index, total, applicationId, stageId):
    component = report['components'][index]

    print(f"Searching for {index+1} of {total} components -- {component['displayName']}")
    packageUrl = {"packageUrl": component["packageUrl"]}
    packList = {"components": [{"packageUrl": component["packageUrl"]}]}

    recommendation_task = asyncio.create_task(get_recommendation(packageUrl, applicationId, stageId))
    versions_task = asyncio.create_task(get_last_version(packageUrl))
    details_task = asyncio.create_task(get_component_details(packList))

    for violations in component["violations"]:
        # maybe pull from raw data ?
        violation = await get_violation(violations["policyViolationId"])
        if violation["policyThreatCategory"] == 'security':
            for constraintViolations in violation["constraintViolations"]:
                for reason in constraintViolations["reasons"]:
                    if reason["reference"]["type"] == 'SECURITY_VULNERABILITY_REFID':
                        CVE = reason["reference"]["value"]
                        reason["reference"].update({"details": await get_vulnerability(CVE)})
        violations.update({"details": violation})

    await asyncio.gather(recommendation_task, versions_task, details_task)
    res = {
            "component": component,
            "recommendation": recommendation_task.result(),
            "versions": versions_task.result(),
            "details": details_task.result(),
        }

    return res

# -----------------------------------------------------------------------------


def pp(c):
    print(json.dumps(c, indent=4))


def dumps(page, pretty=True, file_name="results.json"):
    try:
        if pretty:
            page = json.dumps(page, indent=4)
        with open(file_name, "w+") as file:
            file.write(page)
    finally:
        return page


async def handle_resp(resp, root=""):
    global api_calls
    api_calls += 1
    if resp.status != 200:
        print(await resp.text())
        return None
    node = await resp.json()
    if root in node:
        node = node[root]
    if node is None or len(node) == 0:
        return None
    return node


@lru_cache(maxsize=1024)
@cacheable
async def get_url(url, root=""):
    resp = await iq_session.get(url, auth=iq_auth)
    return await handle_resp(resp, root)


async def post_url(url, params, root=""):
    resp = await iq_session.post(url, json=params, auth=iq_auth)
    return await handle_resp(resp, root)


def get_epoch(epoch_ms):
    dt_ = datetime.datetime.fromtimestamp(epoch_ms/1000)
    return dt_.strftime("%Y-%m-%d %H:%M:%S")


async def get_applicationId(publicId):
    url = f'{iq_url}/api/v2/applications?publicId={publicId}'
    apps = await get_url(url, "applications")
    if apps is None:
        return None
    return apps[0]['id']


async def get_reportId(applicationId, stageId):
    url = f"{iq_url}/api/v2/reports/applications/{applicationId}"
    reports = await get_url(url)
    for report in reports:
        if report["stage"] in stageId:
            return report["reportHtmlUrl"].split("/")[-1]


async def get_policy_violations(publicId, reportId):
    url = f'{iq_url}/api/v2/applications/{publicId}/reports/{reportId}/policy'
    return await get_url(url)


async def get_violation(policyViolationId):
    ''' requires => IQ.93 '''
    url = f'{iq_url}/api/v2/policyViolations/crossStage/{policyViolationId}'
    return await get_url(url)


async def get_component_details(component):
    url = f'{iq_url}/api/v2/components/details'
    return await post_url(url, component)


async def get_recommendation(component, applicationId, stageId):
    url = f'{iq_url}/api/v2/components/remediation/application/{applicationId}?stageId={stageId}'
    return await post_url(url, component)


async def get_vulnerability(vulnerabilityId):
    url = f'{iq_url}/api/v2/vulnerabilities/{vulnerabilityId}'
    return await get_url(url)


async def get_last_version(component):
    url = f"{iq_url}/api/v2/components/versions"
    return await post_url(url, component)
# -----------------------------------------------------------------------------
# -----------------------------------------------------------------------------


if __name__ == "__main__":
    asyncio.run(main())
