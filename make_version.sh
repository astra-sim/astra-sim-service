#!/bin/bash

if [ -n "$1" ]; then
    VERSION="$1"
else
    VERSION=$(cat .VERSION)
fi

if [[ -z "$CI_COMMIT_REF_NAME" ]]; then
    echo "Must provide CI_COMMIT_REF_NAME in environment" 1>&2
    exit 1
fi

if [[ -z "$VERSION_FROM_FILE" ]]; then
    echo "Must provide VERSION_FROM_FILE in environment" 1>&2
    exit 1
fi

BRANCH_NAME=${CI_COMMIT_REF_NAME//-/.}
BRANCH_NAME=${BRANCH_NAME//_/.}
BRANCH=$(git rev-parse --abbrev-ref HEAD)

if [ "$BRANCH" = "main" ]; then
    echo "$VERSION_FROM_FILE"
else
    DISTANCE=$(git rev-list --count $(git merge-base HEAD origin/main)..HEAD)
    # Sanitize branch name for version string (optional)
    # SAFE_BRANCH=$(echo $BRANCH | sed 's/[^a-zA-Z0-9]/-/g')
    echo "${VERSION_FROM_FILE}+${BRANCH_NAME}.${DISTANCE}"
fi