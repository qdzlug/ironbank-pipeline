#!/bin/bash
FILES=${SCAN_DIRECTORY}/*
AWS_KEY="${}"
AWS_SECRET="${3BucketKey}"
S3_BUCKET="${S3_REPORT_BUCKET}"
S3_BUCKET_PATH="/${CI_PROJECT_NAME}-${IMG_VERSION}/${REPORT_DIRECTORY}"

function s3Upload
{
  bucket=${S3_BUCKET}
  bucket_path=${S3_BUCKET_PATH}
  date=$(date +"%a, %d %b %Y %T %z")
  acl="x-amz-acl:private"
  content_type="application/octet-stream"
  sig_string="PUT\n\n$content_type\n$date\n$acl\n/$bucket$bucket_path$file"
  signature=$(echo -en "${sig_string}" | openssl sha1 -hmac "${AWS_SECRET}" -binary | base64)

  curl -X PUT -T "$bucket_path/$f" \
    -H "Host: $bucket.s3.amazonaws.com" \
    -H "Date: $date" \
    -H "Content-Type: $content_type" \
    -H "$acl" \
    -H "Authorization: AWS ${AWS_KEY}:$signature" \
    "https://$bucket.s3.amazonaws.com$bucket_path$file"
}


# loop through the path and upload the files
for f in $FILES
  s3Upload "$path" "${f}" "/"
done
