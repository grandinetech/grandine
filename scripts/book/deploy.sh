#!/bin/sh

# Builds the Grandine Book and uploads the generated HTML to S3.
#
# Usage: scripts/book/deploy.sh s3://<bucket>[/<prefix>]
#
# Required environment variables (unless AWS_PROFILE is set):
# - AWS_ACCESS_KEY_ID           Access key of an IAM user allowed to write to the bucket.
# - AWS_SECRET_ACCESS_KEY       Secret access key of the same user.
#
# Optional environment variables:
# - AWS_DEFAULT_REGION          Region of the bucket. Defaults to eu-central-1.
# - AWS_PROFILE                 AWS CLI profile to use instead of the keys above.
# - CLOUDFRONT_DISTRIBUTION_ID  If set, the distribution's cache is invalidated after upload.
# - DRY_RUN=1                   Show what would be uploaded without changing anything.

set -eu

if [ $# -ne 1 ]; then
    echo "usage: $0 s3://<bucket>[/<prefix>]" >&2
    exit 1
fi

destination=${1%/}

case "$destination" in
    s3://?*) ;;
    *)
        echo "destination must start with s3://" >&2
        exit 1
        ;;
esac

for tool in mdbook aws; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "$tool is not installed" >&2
        exit 1
    fi
done

if [ -z "${AWS_PROFILE:-}" ]; then
    if [ -z "${AWS_ACCESS_KEY_ID:-}" ] || [ -z "${AWS_SECRET_ACCESS_KEY:-}" ]; then
        echo "set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY (or AWS_PROFILE)" >&2
        exit 1
    fi
fi

export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-eu-central-1}"

# AWS CLI v1 on Python 3.12 prints a wall of harmless SyntaxWarnings.
export PYTHONWARNINGS="${PYTHONWARNINGS:-ignore::SyntaxWarning}"

# Fail early on bad credentials instead of after building the book.
if ! aws sts get-caller-identity >/dev/null; then
    echo "AWS rejected the credentials" >&2
    exit 1
fi

book_dir=$(cd "$(dirname "$0")/../../book" && pwd)
output_dir="$book_dir/book"

rm -rf "$output_dir"
(cd "$book_dir" && mdbook build --dest-dir "$output_dir")

# mdBook only logs a failed preprocessor, so check that maintainer notes were stripped.
if grep -rl 'TODO(' "$output_dir" --include='*.html' --include='searchindex.*' >&2; then
    echo "TODO comments leaked into the generated book" >&2
    exit 1
fi

dry_run=
if [ "${DRY_RUN:-}" = 1 ]; then
    dry_run=--dryrun
fi

# `cp` only needs `s3:PutObject`, unlike `sync`, which also needs `s3:ListBucket`.
# Pages removed from the book are therefore left behind in the bucket.
# The bucket serves files through per-object ACLs, so each upload must be made public.
aws s3 cp "$output_dir" "$destination" --recursive --acl public-read $dry_run

if [ -n "${CLOUDFRONT_DISTRIBUTION_ID:-}" ] && [ -z "$dry_run" ]; then
    aws cloudfront create-invalidation \
        --distribution-id "$CLOUDFRONT_DISTRIBUTION_ID" \
        --paths '/*'
fi

echo "Book deployed to $destination"
