# S3: detecting anonymous writes

`rules/aws_s3_anonymous_put_object.yml` matches CloudTrail, but CloudTrail does
not record object-level calls unless data events are enabled for the bucket.
Most accounts that get hit by this have never turned them on. There are three
usable sources.

## CloudTrail data events

Enable them per bucket (or via an organisation trail) for `s3:PutObject`,
`s3:DeleteObject` and `s3:PutObjectAcl`. Once enabled, anonymous requests appear
with:

```json
{
  "eventSource": "s3.amazonaws.com",
  "eventName": "PutObject",
  "userIdentity": { "type": "Anonymous" },
  "sourceIPAddress": "203.0.113.10",
  "userAgent": "[aws-sdk-go/1.44.0]",
  "requestParameters": { "bucketName": "example-bucket", "key": "shell.php" }
}
```

Athena over the CloudTrail table:

```sql
SELECT eventtime, eventname, sourceipaddress, useragent,
       json_extract_scalar(requestparameters, '$.bucketName') AS bucket,
       json_extract_scalar(requestparameters, '$.key') AS object_key
FROM cloudtrail_logs
WHERE eventsource = 's3.amazonaws.com'
  AND eventname IN ('PutObject', 'PutObjectAcl', 'DeleteObject')
  AND json_extract_scalar(useridentity, '$.type') = 'Anonymous'
ORDER BY eventtime DESC;
```

## S3 server access logs

If the bucket has access logging on, anonymous requests have `-` in the
requester field:

```
79a5... example-bucket [05/Nov/2026:08:52:11 +0000] 203.0.113.10 - 3E57... REST.PUT.OBJECT shell.php "PUT /shell.php HTTP/1.1" 200 - 17 - 12 "-" "aws-sdk-go/1.44.0" -
```

Alert on `REST.PUT.OBJECT` (and `REST.POST.UPLOADS`) where the requester is `-`.
The same logs will show a 403 when the write was denied, which is still evidence
of the attempt.

## Configuration review

The rule only fires after the write. Check for the precondition:

```bash
aws s3api get-bucket-acl --bucket example-bucket
# look for URI="http://acs.amazonaws.com/groups/global/AllUsers" with WRITE

aws s3api get-bucket-policy --bucket example-bucket
# look for "Principal": "*" combined with s3:PutObject
```

Also check `Block Public Access` at the account and bucket level. Public write
is not required for the lab technique to work: a bucket policy that allows
`s3:PutObject` to everyone is enough, and it survives most default settings.

## Blind spots

- If data events are off and access logging is off, the write is invisible in
  AWS logs. CloudFront logs help only if the bucket is served through a
  distribution.
- `PutObject` with a presigned URL looks like a normal authenticated call from
  the signer's credentials; the anonymous filter will not see it.
- An attacker who obtained valid keys is not anonymous, so this rule does
  nothing for them. Pair it with a rule for writes from new user agents or
  unusual source addresses.
