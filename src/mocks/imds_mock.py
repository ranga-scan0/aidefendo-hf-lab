#!/usr/bin/env python3
"""Mock AWS IMDS (Instance Metadata Service) at 169.254.169.254.

Returns fake IAM credentials for the node's instance role, matching
the real IMDS v1 response shape that an ALPHA exploit would receive.
Deployed as a hostNetwork DaemonSet so every pod on the node can
curl http://169.254.169.254/... and the sensor sees a real outbound
connect to the IMDS IP (R0068).
"""

import json
import os
from http.server import HTTPServer, BaseHTTPRequestHandler

BIND = os.environ.get("IMDS_BIND", "169.254.169.254")
PORT = int(os.environ.get("IMDS_PORT", "80"))
ROLE = os.environ.get("IMDS_ROLE", "dataset-worker-node-role")

IAM_CREDS = {
    "Code": "Success",
    "LastUpdated": "2026-09-10T12:00:00Z",
    "Type": "AWS-HMAC",
    "AccessKeyId": "ASIAFAKEACCESSKEYID01",
    "SecretAccessKey": "FakeSecretAccessKey0123456789abcdefghij",
    "Token": "FakeSessionToken" + "A" * 200,
    "Expiration": "2026-09-10T18:00:00Z",
}

INSTANCE_ID = "i-0fake1234567890ab"
INSTANCE_TYPE = "m5.xlarge"
REGION = "us-east-1"
AZ = "us-east-1a"
ACCOUNT_ID = "123456789012"


class IMDSHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        p = self.path.rstrip("/")
        body = self._route(p)
        if body is None:
            self.send_response(404)
            self.end_headers()
            return
        if isinstance(body, dict):
            body = json.dumps(body)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_PUT(self):
        # IMDSv2 token request
        if self.path == "/latest/api/token":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"FakeIMDSv2Token123456")
            return
        self.send_response(404)
        self.end_headers()

    def _route(self, path):
        routes = {
            "/latest/meta-data": "ami-id\ninstance-id\ninstance-type\nlocal-ipv4\nplacement/\niam/",
            "/latest/meta-data/ami-id": "ami-0fake1234567890ab",
            "/latest/meta-data/instance-id": INSTANCE_ID,
            "/latest/meta-data/instance-type": INSTANCE_TYPE,
            "/latest/meta-data/local-ipv4": "10.0.1.42",
            "/latest/meta-data/placement/availability-zone": AZ,
            "/latest/meta-data/placement/region": REGION,
            "/latest/meta-data/iam/security-credentials": ROLE,
            f"/latest/meta-data/iam/security-credentials/{ROLE}": IAM_CREDS,
            "/latest/meta-data/iam/info": {
                "Code": "Success",
                "InstanceProfileArn": f"arn:aws:iam::{ACCOUNT_ID}:instance-profile/{ROLE}",
                "InstanceProfileId": "AIPAFAKEPROFILEID0001",
            },
            "/latest/dynamic/instance-identity/document": {
                "accountId": ACCOUNT_ID,
                "instanceId": INSTANCE_ID,
                "region": REGION,
                "availabilityZone": AZ,
                "instanceType": INSTANCE_TYPE,
                "imageId": "ami-0fake1234567890ab",
            },
        }
        return routes.get(path)

    def log_message(self, fmt, *args):
        print(f"[imds] {self.address_string()} {fmt % args}")


if __name__ == "__main__":
    print(f"[imds] mock IMDS listening on {BIND}:{PORT}")
    print(f"[imds] role: {ROLE}")
    srv = HTTPServer((BIND, PORT), IMDSHandler)
    srv.serve_forever()
