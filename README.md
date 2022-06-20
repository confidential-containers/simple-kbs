# Simple Key Broker Server

A Key Broker Server (KBS) verifies the launch measurement of a secure guest and conditionally provides secrets.

This KBS currently supports SEV and SEV-ES with pre-attestation.
The KBS has two gRPC endpoints, `GetBundle` and `GetSecret`. 
These endpoints are described below and defined in the [protobuf](src/grpc/keybroker.proto).

To validate confidential guests, the guest owner must pre-provision the KBS
with policy information. This KBS uses a database to store policies and secrets.
The database is described below.

## API

### GetBundle
The `GetBundle` endpoint takes a policy and certificate chain.
After verifying the certificate chain, the KBS provides a session file and guest owner public key.
This session file defines a secure channel between the KBS and the PSP, which will be used to securely provide secrets.

### GetSecret
The `GetSecret` endpoint takes the launch measurement of the guest, the expected launch parameters, and a secret request. 
The expected launch parameters such as policy and firmware version are used to select the appropriate owner-approved launch digest. 
The cryptographically verified launch measurement guarantees the correctness of the launch parameters. 

The secret request allows the user to request multiple secrets in different formats. 
With SEV and SEV-ES, the secret can only be injected once.
Since the secret must be formulated inside the trusted domain (i.e. the KBS) and there is no way to join together multiple secret blobs, any secrets that the KBC needs at runtime must be in the secret blob generated by the KBS.
Thus, requesting multiple secrets at once is essential.

The JSON bundle secret format is compatible with the Attestation Agent's `offline-sev-kbc`.
The secrets are provided in the OVMF secret table format.

Additional secret types may be supported in the future.


## Policies and Secrets 

In SEV terms the policy is a group of flags that specifies properties of a confidential guest. 
Here the policy also refers more generally to pre-provisioned guidelines that the KBS uses to evaluate the launch measurement of a VM and to determine whether a secret should be injected.
By default the KBS enforces one tenant-wide policy, which is specified in `default_policy.json`.
```
{
  "allowed_digests": [],
  "allowed_policies": [],
  "min_fw_api_major": 0,
  "min_fw_api_minor": 0,
  "allowed_build_ids": []
}
```
Each policy contains five fields.
The guest VM must meet all five requirements for the policy to be validated.
For instance, the guest must boot with a launch digest that is listed in `allowed_digests` or the KBS will not release secrets. 
Note that in fields where multiple options can be specified, such as `allowed_digests`, everything will be allowed if no values are specified.
Thus, the default policy above allows everything.
This can be adjusted so that specific launch digests or firmware versions are required.

Policies can also be specified for individual secrets or groups of secrets via the database.
For a given secret request, the guest must satisfy all associated policies or the secret will not be injected.
Adding additional policies for secrets or keysets cannot make the policy computed for a secret request less restrictive.

Currently the secrets themselves are also stored in the database, although HSM integration is planned.

The database can be configured according to [db.sql](./db.sql).
KBS is connected to database via environment variables.
* `KBS_DB_HOST`
* `KBS_DB_USER`
* `KBS_DB_PW`
* `KBS_DB`

This KBS does not calculate the launch digest. The guest owner must calculate the launch digest ahead of time.
The [sev-snp-measure](https://github.com/IBM/sev-snp-measure) tool can be used to calculate the launch digest of an SEV guest. For example:

    $ sev-snp-measure -v --mode=sev --output-format=base64 \
                      --ovmf=OVMF.fd                       \
                      --kernel=vmlinuz                     \
                      --initrd=kata-containers-initrd.img  \
                      --append="console=ttyS0 loglevel=6"
    Calculated SEV guest measurement: XAI+mQvk/x/kCyHprKj3K7zmXmdm+/7SfpG9AUDWIMQ=

This means that the guest firmware code does not need to be uploaded to the KBS and that SEV and SEV-ES launches follow an identical flow.
The downside is that the guest owner might have to generate more firmware digests ahead of time to account for variations in initrd or CPU count (for SEV-ES guests).



Loosely based on [CCv0 SEV GOP script](https://github.com/confidential-containers-demo/scripts/tree/main/guest-owner-proxy).
