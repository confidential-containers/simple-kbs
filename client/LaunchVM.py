# Copyright (c) 2022 IBM
#
# SPDX-License-Identifier: Apache-2.0
#

import base64
import libvirt
import shutil
import grpc
import hashlib
import sys
from uuid import UUID
from bs4 import BeautifulSoup as bs

from keybroker_pb2_grpc import KeyBrokerServiceStub
from keybroker_pb2 import BundleRequest, SecretRequest, RequestDetails

XML_PATH = "sev_guest.xml"
KBS_URI = "127.0.0.1:44444"

def main():
    hv = libvirt.open("qemu:///system")

    # load and parse XML
    f = open(XML_PATH, "r")
    xml = f.read()
    f.close()

    soup = bs(xml, "xml")
    
    policy = soup.find("policy").text

    # use this to calculate the expected digest
    ovmf_path = soup.find("loader").text
    initrd_path = soup.find("initrd").text
    kernel_path = soup.find("kernel").text
    cmdline = soup.find("cmdline").text

    channel = grpc.insecure_channel(KBS_URI)
    client = KeyBrokerServiceStub(channel)
   
    
    # currrently libvirt cannot export a cert chain with a 
    # signed CEK. instead, use sevctl to export the cert chain
    # and store it in a file.
    f = open("certchain","rb")
    cert_chain_bytes = f.read()
    f.close()
    cert_chain = base64.b64encode(cert_chain_bytes).decode("utf-8")

    request = BundleRequest(CertificateChain = cert_chain, Policy = int(policy, 0))
    try:
        response = client.GetBundle(request)
    except grpc.RpcError as e:
        print("Failed to get Launch Bundle: {}".format(e), file=sys.stderr)
        channel.close()
        exit(1)

    # add godh and session file to XML
    ls = soup.find("launchSecurity")
    cert_tag = soup.new_tag("dhCert")
    cert_tag.string = response.GuestOwnerPublicKey
    ls.append(cert_tag)

    session_tag = soup.new_tag("session")
    session_tag.string = response.LaunchBlob
    ls.append(session_tag)

    xml = str(soup.domain)

    # define the domain from XML
    dom = hv.defineXML(xml) 
    dom.createWithFlags(libvirt.VIR_DOMAIN_START_PAUSED)

    # get launch measurement
    sevinfo = dom.launchSecurityInfo()

    expected_digest = get_expected_digest(ovmf_path, initrd_path, kernel_path, cmdline)

    request = SecretRequest(LaunchMeasurement = sevinfo['sev-measurement'], \
            LaunchId = response.LaunchId, \
            Policy = sevinfo['sev-policy'], \
            ApiMajor = sevinfo['sev-api-major'], \
            ApiMinor = sevinfo['sev-api-minor'], \
            BuildId = sevinfo['sev-build-id'], \
            FwDigest = expected_digest, \
            LaunchDescription = "test launch",
            SecretRequests = [\
                    RequestDetails(Guid = "0a46e24d-478c-4eb1-8696-113eeec3aa99", \
                        Format = "json", \
                        SecretType = "bundle", \
                        Id = "keyset1" )] \
            )
   
    try:
        response = client.GetSecret(request)
    except grpc.RpcError as e:
        print("Failed to get Launch Secret: {}".format(e), file=sys.stderr)
        channel.close()
        exit(1)


    params = {"sev-secret": response.LaunchSecretData,
              "sev-secret-header": response.LaunchSecretHeader}
    dom.setLaunchSecurityState(params, 0)
    dom.resume()

    hv.close()

# calculate the expected launch digest 
# this will be verified via he measurement
# so it's fine for the CSP to calculate 
# this here
def get_expected_digest(ovmf, initrd, kernel, cmdline):

    fh = open(initrd, 'rb')
    h = hashlib.sha256(fh.read())
    initrd_hash = h.digest()

    fh = open(kernel, 'rb')
    h = hashlib.sha256(fh.read())
    kernel_hash = h.digest()

    cmdline = bytearray(cmdline, encoding='utf8')

    # remove trailing `\n` if present
    cl = len(cmdline)
    if (cmdline[cl-1] == 0xa):
        cl -= 1

    # add trailing '\0'
    cmdline[cl:cl+1] = (0).to_bytes(1, byteorder='little')
    h = hashlib.sha256(cmdline)
    cmdline_hash = h.digest()

    h = hashlib.sha256();
    fh = open(ovmf, 'rb');
    h.update(fh.read());
    hashes = bytearray()
    hashes[0:16]= UUID('{9438d606-4f22-4cc9-b479-a793d411fd21}').bytes_le
    l = 16 + 2                   # GUID + 2 byte length
    hashes[16:18] = l.to_bytes(2, byteorder='little')

    hashes[l:l+16] = UUID('{97d02dd8-bd20-4c94-aa78-e7714d36ab2a}').bytes_le
    l += 16
    hashes[l:l+2] = (16 + 2 + 32).to_bytes(2, byteorder='little')
    l += 2
    hashes[l:l+32] = cmdline_hash
    l += 32

    hashes[l:l+16] = UUID('{44baf731-3a2f-4bd7-9af1-41e29169781d}').bytes_le
    l += 16
    hashes[l:l+2] = (16 + 2 + 32).to_bytes(2, byteorder='little')
    l += 2
    hashes[l:l+32] = initrd_hash
    l += 32

    hashes[l:l+16] = UUID('{4de79437-abd2-427f-b835-d5b172d2045b}').bytes_le
    l += 16
    hashes[l:l+2] = (16 + 2 + 32).to_bytes(2, byteorder='little')
    l += 2
    hashes[l:l+32] = kernel_hash
    l += 32

    hashes[16:18] = l.to_bytes(2, byteorder='little')

    # pad up to multiple of 16
    pl = 15 - ((l + 15) & 15)

    if (pl):
        hashes[l:l+pl] = (0).to_bytes(pl, byteorder='little')
        l += pl

    h.update(hashes)

    return base64.b64encode(h.digest()).decode("utf-8")



if __name__ == "__main__":
    main()
