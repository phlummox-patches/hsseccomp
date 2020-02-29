#!/usr/bin/env bash

# run 'stack-only' tests with some resolver

if [ "$#" -ne 1 ]; then
  echo "expected one arg, a resolver to use (e.g. 'lts-11')"
  exit 1
fi

export STACK_RESOLVER="$1"
stack --resolver="${STACK_RESOLVER}" init
STACK_YAML_FILE=stack-"${STACK_RESOLVER}".yaml
mv stack.yaml "$STACK_YAML_FILE"
stack --resolver="${STACK_RESOLVER}" --stack-yaml "$STACK_YAML_FILE" test --flag hsseccomp:stack-based-tests --test-arguments '+RTS -C0'

