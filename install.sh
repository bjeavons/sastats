#!/usr/bin/env bash

# Create data export directories

if [ ! -d "$PWD/data/core/html" ]; then
  mkdir -p ${PWD}/data/core/html
fi
if [ ! -d "$PWD/data/core/json" ]; then
  mkdir -p ${PWD}/data/core/json
fi
if [ ! -d "$PWD/data/contrib/html" ]; then
  mkdir -p ${PWD}/data/contrib/html
fi
if [ ! -d "$PWD/data/contrib/json" ]; then
  mkdir -p ${PWD}/data/contrib/json
fi

# Run composer install

if [ ! -d "$PWD/vendor" ]; then
  composer install
fi
