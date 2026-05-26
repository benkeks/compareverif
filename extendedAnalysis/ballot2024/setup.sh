#!/bin/bash

git clone https://github.com/gballot/mtd.git

cd mtd
git checkout 0061a4ebea9230b75ce8b8fe943f3e06edec
git am ../0001-Add-xml-parser.patch
