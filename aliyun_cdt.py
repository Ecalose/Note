#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
# Author:  MoeClub.org

# pip3 install aiohttp aiohttp-socks
from aiohttp import client
from aiohttp_socks import ProxyConnector
from urllib import parse
import asyncio
import datetime
import hashlib
import json
import hmac
import uuid
import time


class Utils:
    @staticmethod
    async def http(method, url, headers=None, cookies=None, data=None, redirect=True, proxy=None, timeout=30, loop=None):
        method = str(method).strip().upper()
        if method not in {"GET", "HEAD", "POST", "PUT", "DELETE", "PATCH"}:
            raise ValueError(f"HTTP Method Not Allowed [{method}].")

        Headers = ({ str(key).strip(): str(value).strip() for key, value in headers.items() } if headers is not None else { "User-Agent": "Mozilla/5.0", "Accept-Encoding": ""})
        respData = {"code": None, "data": None, "headers": None, "cookies": None, "url": None, "req": None, "err": None}
        Connector = None

        try:
            proxyUrl = "" if proxy is None else str(proxy).strip()

            connectorArgs = {"ssl": False, "force_close": True, "enable_cleanup_closed": True, "use_dns_cache": False}
            if loop is not None:
                connectorArgs["loop"] = loop

            if proxyUrl:
                Connector = ProxyConnector.from_url(proxyUrl, **connectorArgs)
            else:
                Connector = client.TCPConnector(**connectorArgs)

            async with client.ClientSession(connector=Connector, connector_owner=True, timeout=client.ClientTimeout(total=timeout)) as session:
                async with session.request(method=method, url=url, headers=Headers, cookies=cookies, data=data, allow_redirects=redirect, raise_for_status=False) as resp:
                    respData["code"] = resp.status
                    respData["headers"] = resp.headers
                    respData["cookies"] = resp.cookies
                    respData["url"] = str(resp.url)
                    # respData["req"] = resp.request_info
                    respData["data"] = await resp.read()
        except Exception as e:
            if respData["code"] is None:
                respData["code"] = 555
            if respData["data"] is None:
                respData["data"] = b""
            respData["err"] = str(e)

        finally:
            if Connector is not None and not Connector.closed:
                await Connector.close()

        return respData

    @staticmethod
    def Sign(key: str, secret: str, method: str, url: str,  token=None, headers=None, body=None, **kwargs):
        algorithm = "ACS3-HMAC-SHA256"
        method = str(method).strip().upper()
        if not method:
            raise ValueError("method must not be empty")

        reqUrl = parse.urlsplit(url)
        if reqUrl.scheme.lower() not in ("http", "https") or not reqUrl.netloc:
            raise ValueError("url must be an absolute HTTP or HTTPS URL")
        if reqUrl.username is not None or reqUrl.password is not None:
            raise ValueError("url must not contain user information")

        if body is None:
            bodyRaw = b""
        elif isinstance(body, bytes):
            bodyRaw = body
        elif isinstance(body, (bytearray, memoryview)):
            bodyRaw = bytes(body)
        elif isinstance(body, str):
            bodyRaw = body.encode("utf-8")
        else:
            raise TypeError("body must be str, bytes, bytearray, memoryview, or None")

        # Copy instead of mutating the caller's dictionary.  Header lookup and
        # replacement below are case-insensitive, as required by HTTP.
        headers = {} if headers is None else dict(headers)

        def setHeader(name, value):
            matched = [item for item in headers if str(item).strip().lower() == name.lower()]
            if matched:
                headers[matched[0]] = value
                for item in matched[1:]:
                    del headers[item]
            else:
                headers[name] = value

        def getHeader(name):
            for item, value in headers.items():
                if str(item).strip().lower() == name.lower():
                    return value
            return None

        setHeader("Host", reqUrl.netloc)

        action = kwargs.get("action")
        version = kwargs.get("version")
        if action is not None:
            setHeader("X-Acs-Action", str(action).strip())
        if version is not None:
            setHeader("X-Acs-Version", str(version).strip())

        if not str(getHeader("X-Acs-Action") or "").strip():
            raise ValueError("action or X-Acs-Action header is required")
        if not str(getHeader("X-Acs-Version") or "").strip():
            raise ValueError("version or X-Acs-Version header is required")

        acsDate = kwargs.get("date")
        if acsDate is not None:
            setHeader("X-Acs-Date", str(acsDate).strip())
        elif getHeader("X-Acs-Date") is None:
            timeNow = datetime.datetime.now(datetime.timezone.utc)
            setHeader("X-Acs-Date", timeNow.strftime("%Y-%m-%dT%H:%M:%SZ"))

        nonce = kwargs.get("nonce")
        if nonce is not None:
            setHeader("X-Acs-Signature-Nonce", str(nonce).strip())
        elif getHeader("X-Acs-Signature-Nonce") is None:
            setHeader("X-Acs-Signature-Nonce", uuid.uuid4().hex)

        if token is not None:
            setHeader("X-Acs-Security-Token", str(token).strip())

        payloadHash = hashlib.sha256(bodyRaw).hexdigest()
        setHeader("X-Acs-Content-Sha256", payloadHash)

        # RFC 3986 encoding: spaces are %20, never '+', while -_.~ remain raw.
        def percentEncode(value):
            return parse.quote(str(value), safe="-_.~", encoding="utf-8", errors="strict")

        queryRaw = parse.parse_qsl(reqUrl.query, keep_blank_values=True)
        queryRaw.sort(key=lambda item: (item[0], item[1]))
        query = [
            "{}={}".format(percentEncode(name), percentEncode(value))
            for name, value in queryRaw
        ]

        rawPath = "/" if reqUrl.path == "" else reqUrl.path
        if str(kwargs.get("style", "")).strip().upper() == "RPC":
            rawPath = "/"
        canonicalUri = "/".join(
            percentEncode(parse.unquote(item, encoding="utf-8", errors="strict"))
            for item in rawPath.split("/")
        )
        if not canonicalUri.startswith("/"):
            canonicalUri = "/" + canonicalUri

        # Only host, content-type, and x-acs-* headers participate in ACS3.
        # Authorization is deliberately excluded because it is produced below.
        header = {}
        for name, value in headers.items():
            headerName = str(name).strip().lower()
            if value is not None and (
                headerName == "host"
                or headerName == "content-type"
                or headerName.startswith("x-acs-")
            ):
                header[headerName] = str(value).strip()
        headerKey = sorted(header)

        reqArray = [method, canonicalUri, "&".join(query)]
        for item in headerKey:
            reqArray.append("{}:{}".format(item, header[item]))
        reqArray.append("")
        reqArray.append(";".join(headerKey))
        reqArray.append(payloadHash)

        canonicalRequest = "\n".join(reqArray)
        signArray = [
            algorithm,
            hashlib.sha256(canonicalRequest.encode("utf-8")).hexdigest(),
        ]
        signature = hmac.new(
            str(secret).encode("utf-8"),
            "\n".join(signArray).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        setHeader(
            "Authorization",
            "{} Credential={},SignedHeaders={},Signature={}".format(
                algorithm, key, ";".join(headerKey), signature
            ),
        )

        newUrl = "{}://{}{}{}".format(
            reqUrl.scheme.lower(),
            reqUrl.netloc,
            canonicalUri,
            "" if len(query) == 0 else ("?" + "&".join(query)),
        )
        if method == "POST":
            setHeader("Content-Length", str(len(bodyRaw)))

        return method, newUrl, headers


class Aliyun:
    def __init__(self, key, secret):
        self.key = key
        self.secret = secret

    def Headers(self, **kwargs):
        headers = {
            "User-Agent": "AliyunAPI/1.0",
            "Accept": "application/json",
        }
        for key, value in kwargs.items():
            headers[key] = value
        return headers

    async def Metric(self, region, instanceId):
        now = time.localtime()
        tz = datetime.timezone(datetime.timedelta(seconds=now.tm_gmtoff))
        monthStart = datetime.datetime(now.tm_year, now.tm_mon, 1, 0, 0, 0, tzinfo=tz)
        monthStartNext = datetime.datetime(now.tm_year + 1, 1, 1, 0, 0,0, tzinfo=tz) if now.tm_mon == 12 else datetime.datetime(now.tm_year, now.tm_mon + 1, 1, 1, 0, 0,0, tzinfo=tz)
        calcEnd = min(datetime.datetime.now(tz).replace(second=0, microsecond=0), monthStartNext)
        if calcEnd <= monthStart:
            return None, None
        calcHour = calcEnd.replace(minute=0, second=0, microsecond=0)
        endpoint = "https://metrics.{}.aliyuncs.com/".format(region)

        async def fetch(metric, startTime, endTime, period):
            startTime, endTime = min(startTime, endTime), max(startTime, endTime)

            maxSpan = datetime.timedelta(seconds=period * 1400)
            points = {}

            startUTC = startTime.astimezone(datetime.timezone.utc)
            endUTC = endTime.astimezone(datetime.timezone.utc)
            cursor = startUTC

            while cursor < endUTC:
                chunkEnd = min(cursor + maxSpan, endUTC)

                nextToken = None
                while True:
                    payload = {
                        "Namespace": "acs_ecs_dashboard",
                        "MetricName": metric,
                        "Dimensions": json.dumps([{"instanceId": instanceId}], separators=(",", ":")),
                        "StartTime": str(int(cursor.timestamp() * 1000)),
                        "EndTime": str(int(chunkEnd.timestamp() * 1000)),
                        "Period": str(period),
                        "Length": "1440",
                    }
                    if nextToken is not None:
                        payload["NextToken"] = nextToken
                    url = endpoint + "?" + parse.urlencode(payload, quote_via=parse.quote, safe="")
                    method, url, headers = Utils.Sign(self.key, self.secret, method="GET", url=url, token=None, headers=self.Headers(), body=None, action="DescribeMetricList", version="2019-01-01", style="RPC")
                    resp = await Utils.http(method=method, url=url, headers=headers)
                    if resp["code"] != 200:
                        return points
                    respJson = json.loads(resp["data"].decode())
                    rows = respJson.get("Datapoints") or []
                    if isinstance(rows, str):
                        rows = json.loads(rows)
                    if not isinstance(rows, list):
                        rows = []

                    for row in rows:
                        try:
                            timestamp = int(row.get("timestamp"))
                            pointTime = datetime.datetime.fromtimestamp(timestamp / 1000, datetime.timezone.utc)
                        except:
                            continue

                        if cursor < pointTime <= chunkEnd:
                            points[(timestamp, row.get("ip"))] = row

                    nextToken = respJson.get("NextToken")
                    if not nextToken:
                        break

                cursor = chunkEnd
            return points

        def sumPoints(points, period):
            total = 0
            for point in points.values():
                total += float(point.get("Average", None) or 0) * period / 8
            return total

        txHour = sumPoints(await fetch("VPC_PublicIP_InternetOutRate", monthStart, calcHour,3600), 3600)
        rxHour = sumPoints(await fetch("VPC_PublicIP_InternetInRate", monthStart, calcHour,3600), 3600)
        txMinute = sumPoints(await fetch("VPC_PublicIP_InternetOutRate", calcHour, calcEnd,60), 60)
        rxMinute = sumPoints(await fetch("VPC_PublicIP_InternetInRate", calcHour, calcEnd,60), 60)

        txBytes, rxBytes = txHour + txMinute, rxHour + rxMinute
        txGB, rxGB = txBytes / (1024 ** 3), rxBytes / (1024 ** 3)
        # return txBytes, rxBytes
        return txGB, rxGB

    async def Stop(self, region, instanceId):
        endpoint = "https://ecs.{}.aliyuncs.com/".format(region)
        payload = {
            "InstanceId": instanceId,
            "ForceStop": "true",
            "StoppedMode": "StopCharging",
        }
        url = endpoint + "?" + parse.urlencode(payload, quote_via=parse.quote, safe="")
        method, url, headers = Utils.Sign(self.key, self.secret, method="GET", url=url, token=None, headers=self.Headers(), body=None, action="StopInstance", version="2014-05-26", style="RPC")
        resp = await Utils.http(method=method, url=url, headers=headers)
        return True if resp["code"] == 200 else False

    async def Start(self, region, instanceId):
        endpoint = "https://ecs.{}.aliyuncs.com/".format(region)
        payload = { "InstanceId": instanceId }
        url = endpoint + "?" + parse.urlencode(payload, quote_via=parse.quote, safe="")
        method, url, headers = Utils.Sign(self.key, self.secret, method="GET", url=url, token=None, headers=self.Headers(), body=None, action="StartInstance", version="2014-05-26", style="RPC")
        resp = await Utils.http(method=method, url=url, headers=headers)
        return True if resp["code"] == 200 else False

    async def List(self, *args):
        endpoint = "https://ecs.aliyuncs.com/"
        payload = {"AcceptLanguage": "zh-CN"}
        url = endpoint + "?" + parse.urlencode(payload, quote_via=parse.quote, safe="")
        method, url, headers = Utils.Sign(self.key, self.secret, method="GET", url=url, token=None, headers=self.Headers(), body=None, action="DescribeRegions", version="2014-05-26", style="RPC")
        resp = await Utils.http(method=method, url=url, headers=headers)
        if resp["code"] != 200:
            return []
        respJson = json.loads(resp["data"].decode())
        regions = (respJson.get("Regions") or {}).get("Region") or []
        result = []

        for region in regions:
            regionId = region.get("RegionId")
            if args is not None and len(args) > 0:
                if regionId not in args:
                    continue
            endpoint = "https://ecs.{}.aliyuncs.com/".format(regionId)
            nextToken = None

            while True:
                payload = {
                    "RegionId": regionId,
                    "MaxResults": "100",
                }
                if nextToken is not None:
                    payload["NextToken"] = nextToken
                url = endpoint + "?" + parse.urlencode(payload, quote_via=parse.quote, safe="")
                method, url, headers = Utils.Sign(self.key, self.secret, method="GET", url=url, token=None, headers=self.Headers(), body=None, action="DescribeInstances", version="2014-05-26", style="RPC")
                resp = await Utils.http(method=method, url=url, headers=headers)
                if resp["code"] != 200:
                    break
                respJson = json.loads(resp["data"].decode())
                instances = (respJson.get("Instances") or {}).get("Instance") or []

                for instance in instances:
                    publicIpAddress = []
                    publicIps = (instance.get("PublicIpAddress") or {}).get("IpAddress") or []
                    if isinstance(publicIps, str):
                        publicIps = [publicIps]
                    for ipAddress in publicIps:
                        if ipAddress and ipAddress not in publicIpAddress:
                            publicIpAddress.append(ipAddress)
                    eipAddress = (instance.get("EipAddress") or {}).get("IpAddress")
                    if eipAddress and eipAddress not in publicIpAddress:
                        publicIpAddress.append(eipAddress)

                    result.append({
                        "region": regionId,
                        "instanceId": instance.get("InstanceId"),
                        "status": instance.get("Status"),
                        "ipAddress": ",".join(publicIpAddress),
                    })

                nextToken = respJson.get("NextToken", None)
                if nextToken is None or nextToken == "":
                    break

        return result

    async def Check(self, interval=180, txMax=185, region=[]):
        actionMonth = 0
        while True:
            subTime = time.time()
            localMonth = time.localtime().tm_mon
            instances = await self.List(*region)
            for item in instances:
                if actionMonth != localMonth:
                    if item["status"] in ["Stopped"]:
                        status = await self.Start(region=item["region"], instanceId=item["instanceId"])
                        print("[{}] [{}] [{}]: START [{}]".format(time.strftime("%Y/%m/%d %H:%M:%S"), item["region"], item.get("ipAddress", item.get("instanceId")), status))
                        continue
                if item["status"] not in ["Running"]:
                    continue
                tx, rx = await self.Metric(region=item["region"], instanceId=item["instanceId"])
                print("[{}] [{}] [{}]: ↓ {} ↑ {}".format(time.strftime("%Y/%m/%d %H:%M:%S"), item["region"], item.get("ipAddress", item.get("instanceId")), "%.03f" % rx, "%.03f" % tx))
                if tx >= txMax:
                    status = await self.Stop(region=item["region"], instanceId=item["instanceId"])
                    print("[{}] [{}] [{}]: STOP [{}]".format(time.strftime("%Y/%m/%d %H:%M:%S"), item["region"], item.get("ipAddress", item.get("instanceId")), status))
                    actionMonth = localMonth
            await asyncio.sleep(delay=interval - (time.time() - subTime))



if __name__ == "__main__":
    aliyun = Aliyun(key="xxx", secret="xxx")
    asyncio.run(aliyun.Check(interval=180, txMax=185, region=["cn-hongkong"]))
