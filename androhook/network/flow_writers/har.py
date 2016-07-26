#!/usr/bin/env python

import binascii
import json
import sys

from datetime import datetime
from mitmproxy import flow, version


def create_har(flows):
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "MITMPROXY", "version": version.VERSION},
            "entries": [format_flow(fl) for fl in flows]
        }
    }


def format_flow(fl):
    assert isinstance(fl, flow.HTTPFlow)
    result = {
        "startedDateTime": format_timestamp(fl),
        "time": flow_total_duration(fl),
        "request": format_request(fl.request),
        "response": format_response(fl.response),
        "cache": {},  # mitmproxy is not cache-aware
        "timings": format_flow_timings(fl),
        "serverIPAddress": fl.server_conn.address.address[0],
        "connection": str(fl.client_conn.address.address[1])
    }
    return result


def format_request(request):
    result = {
        'method': request.method,
        'url': request.url,
        'httpVersion': request.http_version,
        'cookies': format_request_cookies(request.cookies),
        'headers': format_headers(request.headers),
        'queryString': format_query_parameters(request.query),
        'headersSize': len(str(request.headers)),
    }

    if request.content:
        result['postData'] = format_request_data(request)
        result['bodySize'] = len(request.content)
    else:
        result['bodySize'] = -1

    return result


def format_response(response):
    result = {
        'status': response.status_code,
        'statusText': response.reason,
        'httpVersion': response.http_version,
        'cookies': format_response_cookies(response.cookies),
        'headers': format_headers(response.headers),
        'content': format_response_data(response),
        'redirectURL': response.headers.get('Location', ''),
        'headersSize': len(str(response.headers)),
        'bodySize': len(response.content),
    }
    return result


def format_timestamp(fl):
    # currently we don't keep the dns or tcp timings, so the earliest
    # timestamps for us to use is the request send time.
    timestamp = fl.request.timestamp_start
    return datetime.utcfromtimestamp(timestamp).isoformat() + '+00:00'


def round_timestamp(ts):
    return int(ts * 1000)


def flow_total_duration(fl):
    # FIXME: what if there's no response?
    return round_timestamp(fl.response.timestamp_end) - round_timestamp(fl.request.timestamp_start)


def format_flow_timings(fl):
    return {
        # event though the documentation says we should not add 'blocked','dns' and 'connect',
        # the online viewer will not without those
        'blocked': -1,
        'dns': -1,
        'connect': -1,
        'send': round_timestamp(fl.request.timestamp_end) - round_timestamp(fl.request.timestamp_start),
        'wait': round_timestamp(fl.response.timestamp_start) - round_timestamp(fl.request.timestamp_end),
        'receive': round_timestamp(fl.response.timestamp_end) - round_timestamp(fl.response.timestamp_start),
    }


def format_headers(headers):
    if not headers:
        return []
    return [{"name": key, "value": value} for key, value in headers.items()]


def format_query_parameters(query_parameters):
    if not query_parameters:
        return []
    return [{"name": key, "value": value} for key, value in query_parameters.items()]


def format_request_cookies(cookies):
    if not cookies:
        return []
    return [{"name": key, "value": value} for key, (value, parameters) in cookies.items()]


def format_response_cookies(cookies):
    if not cookies:
        return []
    result = []
    for key, (value, parameters) in cookies.items():
        cookie = {"name": key, "value": value}
        for param in ("path", "domain", "expires"):
            if param in parameters:
                cookie[param] = parameters[param]
        if "httponly" in parameters:
            cookie["httpOnly"] = True
        if "secure" in parameters:
            cookie["secure"] = True
        result.append(cookie)
    return result


def format_request_data(request):
    assert (request)
    assert (request.content)
    urlencoded_parameters = request.urlencoded_form
    content_type = request.headers.get('Content-Type', '')
    if urlencoded_parameters:
        return {
            "mimeType": content_type,
            "params": format_urlencoded_parameters(urlencoded_parameters),
            "text": "",
        }
    elif request.content:
        return {
            "mimeType": content_type,
            "params": [],
            "text": binascii.b2a_base64(request.content).strip(),
            "encoding": "base64",
        }


def format_urlencoded_parameters(urlencoded_parameters):
    if not urlencoded_parameters:
        return []
    return [{"name": key, "value": value} for key, value in urlencoded_parameters.items()]


def format_response_data(response):
    content_type = response.headers.get('Content-Type', '')
    if response.content:
        # we always use base64, avoiding the need to check that the content is in utf8.
        # we use strip to remove the newline the base64 encoding adds
        data = binascii.b2a_base64(response.content).strip()
        return {
            "size": len(data),
            "mimeType": content_type,
            "text": data,
            "encoding": "base64",
        }
    else:
        return {
            "mimeType": content_type,
            "size": 0
        }


def format_redirect_url(response):
    return response.headers.get_first("location", "")


def har_write(input_filename, output_filename):
    with open(input_filename) as input_file, open(output_filename, 'w') as output_file:
        flow_reader = flow.FlowReader(input_file)
        flows = [fl for fl in flow_reader.stream() if fl.response]
        har = create_har(flows)
        output_file.write(json.dumps(har))


def main():
    if len(sys.argv) < 3:
        print "usage: %s input_dump_file output_har_file" % sys.argv[0]
        sys.exit(0)

    har_write(sys.argv[1], sys.argv[2])


if __name__ == '__main__':
    main()
