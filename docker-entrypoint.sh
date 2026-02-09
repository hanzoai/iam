#!/bin/bash

if [ -z "${driverName:-}" ]; then
  export driverName=sqlite
fi
if [ -z "${dataSourceName:-}" ]; then
  export dataSourceName="file:iam.db?cache=shared"
fi

exec /server
