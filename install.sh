#!/usr/bin/env bash

# Create data export directories

if [ ! -d "$PWD/data/core/html" ]; then
  mkdir -p ${PWD}/data/core/html
fi
if [ ! -d "$PWD/data/contrib/html" ]; then
  mkdir -p ${PWD}/data/contrib/html
fi

# Run composer install

if [ ! -d "$PWD/vendor" ]; then
  composer install
fi

