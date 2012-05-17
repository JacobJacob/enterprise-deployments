#!/bin/bash
#
# Copyright 2012 Google Inc. All Rights Reserved.
# Author: mirons@google.com (Michael Irons)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
###########################################################################
# DISCLAIMER:
#
# (i) GOOGLE INC. ("GOOGLE") PROVIDES YOU ALL CODE HEREIN "AS IS" WITHOUT ANY
# WARRANTIES OF ANY KIND, EXPRESS, IMPLIED, STATUTORY OR OTHERWISE, INCLUDING,
# WITHOUT LIMITATION, ANY IMPLIED WARRANTY OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NON-INFRINGEMENT; AND

# (ii) IN NO EVENT WILL GOOGLE BE LIABLE FOR ANY LOST REVENUES, PROFIT OR DATA,
# OR ANY DIRECT, INDIRECT, SPECIAL, CONSEQUENTIAL, INCIDENTAL OR PUNITIVE
# DAMAGES, HOWEVER CAUSED AND REGARDLESS OF THE THEORY OF LIABILITY, EVEN IF
# GOOGLE HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES, ARISING OUT OF
# THE USE OR INABILITY TO USE, MODIFICATION OR DISTRIBUTION OF THIS CODE OR ITS
# DERIVATIVES.
###########################################################################
#
# Description: This bash script uses external utilities like: xmllint, gdalinfo
#              (distributed with Google Earth) as well as and various common
#              linux utilities like find, wc, dirname, sha1sum, etc.
#
#              It uses the utilites to verify several things that are important
#              to proper data ingestion by Google Earth Builder.  For example,
#              we check that the Google Earth Builder files validate against a
#              known schema, that there is only one Google Earth builder file
#              in a directory, that the files referenced in the Google Earth
#              Builder file are valid images, and the option of generating
#              sha1 checksums for all of the images.
#
# Usage: See usage() below.
#

# GLOBALS
TIMESTAMP="$(date '+%F_%H%M%S')"
CHECKSUM=''
CHECKSUM_FILE="$(echo ${PWD}/geb_validator_${TIMESTAMP}.checksum)"
DATA_DIR=''
EBM_FILES=''
LOG_FILE="$(echo ${PWD}/geb_validator_${TIMESTAMP}.log)"
REQ_PROGRAMS="dirname echo find gdalinfo grep sort tee uniq wc xargs xmllint"
SCHEMA_FILE=''
XSLT_FILE=''

#######################################
# Use find to locate .ebm files in our DATA_DIR
# Globals:
#   DATA_DIR
# Arguments:
#   None
# Returns:
#   Space seperated list of full paths to ebm files
#######################################
function locate_ebm_files {

  local our_located_ebm_files=''
  our_located_ebm_files="$(find $DATA_DIR -iregex ".*\(ebm\)$")"
  if [[ -n $our_located_ebm_files ]]; then
    echo $our_located_ebm_files
  else
    echo "  Failure: We were unable to locate any Google Earth Builder Files" \
          | tee -a $LOG_FILE
    exit 1
  fi

}

#######################################
# Make sure we have one Google Earth Builder
# file per directory
# Globals:
#   LOG_FILE
#   SCHEMA_FILE
# Arguments:
#   $@ should be the output of locate_ebm_files()
# Returns:
#   None
#######################################
function validate_data_dir {

  # Use the value of $@ for our geb_files,
  # which should be the output of locate_ebm_files()
  # and passed into check_valid_images.
  local geb_files="$@"
  # Find all of our UNIQUE Google Earth Builder directories for our use below.
  local geb_dirnames="$(echo $geb_files \
                        | xargs -n 1 dirname \
                        | sort \
                        | uniq)"

  # Initalize: f is for failures, s for success, gebs for the found geb files,
  # and dir_prefix to hold the directory of each ebm file.
  local f=0
  local gebs=''
  local dir_prefix=''

  # Look into each directory we found an .ebm file in and try to find another,
  # hoping we don't.
  echo "Process: Checking for > 1  Google Earth Builder file in a directory" \
        | tee -a $LOG_FILE
  for gebs in $geb_dirnames; do
    number_of_ebm_files="$(find $gebs -regex '.*\(ebm\)$' \
                            | wc -l)"
    echo -n "  Verifying: $gebs/... "
    if [[ $number_of_ebm_files -gt 1 ]]; then
      echo "Error"
      let "f++"
      echo "Error: $gebs/ has more than 1 Google Earth Builder file" &>> $LOG_FILE
    else
      echo "OK"
    fi
  done

  # Check the success/failure of actions above, we can't tolerate failures.
  if [[ "$f" -eq 0 ]]; then
    echo "  Success: Found one Google Earth Builder file in each directory" \
          | tee -a $LOG_FILE
  else
    echo "  Failure: More than one Google Earth Builder file in a directory" \
          | tee -a $LOG_FILE
    echo "    Refer to $LOG_FILE for details... exiting"
    exit 1
  fi

}
#######################################
# Test the geb file against the schema
# and make sure we dont find more than
# one per directory.
# Globals:
#   LOG_FILE
#   SCHEMA_FILE
# Arguments:
#   $@ should be the output of locate_ebm_files()
# Returns:
#   None
#######################################
function validate_ebm_against_schema {

  # Use the value of $@ for our geb_files,
  # which should be the output of locate_ebm_files()
  # and passed into check_valid_images.
  local geb_files="$@"

  # Initialize: f is for failures, s is for successes. Reusing gebs and
  # dir_prefix (after a re-initalization) from above.
  local f=0
  local s=0
  local dir_prefix=''

  # Loop through all found Google Earth Builder files and check them against the
  # schema. Log the ones that fail and then check if any failures occured and
  # exit.
  echo "Process: Checking the Google Earth Builder files against the schema" \
        | tee -a $LOG_FILE
  for gebs in $geb_files; do
    local dir_prefix="$(dirname $gebs)"
    echo -n "  Verifying: $gebs... "
    xmllint --noout --schema $SCHEMA_FILE $gebs &> /dev/null
    if [[ $? -eq 0 ]]; then
      echo "OK"
      let "s++"
    else
      echo "Error"
      let "f++"
      xmllint --noout --schema $SCHEMA_FILE $gebs &>> $LOG_FILE
    fi
  done

  # Check the success/failure of actions above, we can't tolerate failures.
  if [[ "$f" -eq 0 ]]; then
    echo "  Success: Verified all Google Earth Builder Files ($s)" \
          | tee -a $LOG_FILE
  else
    echo "  Failure: Unable to validate some Google Earth Builder Files"
    echo "    Refer to $LOG_FILE for details... exiting"
    exit 1
  fi

}

#######################################
# Check to make sure the referenced files
# exist in the folder structure and are
# valid images.
# Globals:
#   LOG_FILE
# Arguments:
#   $@ should be the output of locate_ebm_files()
# Returns:
#   None
#######################################
function check_valid_images {

  # Use the value of $@ for our geb_files,
  # which should be the output of locate_ebm_files()
  # and passed into check_valid_images.
  local geb_files="$@"

  # Initalize: f is for failures, s for success, i is the increment
  # counter for the loop below, images for the found images,
  # and dir_prefix to hold the directory of each ebm file.
  local f=0
  local s=0
  local i=0
  local images=''
  local dir_prefix=''

  # Get a list of all the images from the Google Earth builder
  # files.  Then attempt to run gdalinfo installed with Google Earth Fusion)
  # and check the returncode for success.
  echo "Process: Checking for valid images" \
        | tee -a $LOG_FILE
  for gebs in $geb_files; do
    local dir_prefix="$(dirname $gebs)"
    local images="$(cat $gebs | awk -F'</?sidecar>' 'NF>1{print $2}')"
    images+="$(cat $gebs | awk -F'</?filename>' 'NF>1{print $2}')"
    for i in $images; do
      # Prepend the directory of the Google Earth Builder file we are working on.
      gdalinfo $dir_prefix/$i &> /dev/null
      echo -n "  Verifying: $dir_prefix/$i...  "
      if [[ $? -eq 0 ]]; then
        echo "OK"
        let "s++"
      else
        echo "Error"
        let "f++"
        gdalinfo $dir_prefix/$i &>> $LOG_FILE
      fi
    done
  done

  # Check the success/failure of actions above, we can't tolerate failures.
  if [[ "$f" -eq 0 ]]; then
    echo "  Success: Verified all images ($s)" \
          | tee -a $LOG_FILE
  else
    echo "  Failure: Unable to verify some images ($f)"
    echo "    Refer to $LOG_FILE for details... exiting"
    exit 1
  fi
}

#######################################
# Create a checksum for all of our images
# Globals:
#   DATADIR
#   XSLT_FILE
# Arguments:
#   $@ should be the output of locate_ebm_files()
# Returns:
#   None
#######################################
function checksum_images {

  # Use the value of $@ for our geb_files,
  # which should be the output of locate_ebm_files()
  # and passed into check_valid_images.
  local geb_files="$@"

  # Initalize: f is for failures, s for success, i is the increment
  # counter for the loop below, images for the found images,
  # and dir_prefix to hold the directory of each ebm file.
  local f=0
  local s=0
  local i=0
  local images=''
  local dir_prefix=''

  # Get a list of all the images from the Google Earth builder
  # and create a sha1checksum for them.
  echo "Process: Creating a sha1 checksum file for all images" \
        | tee -a $LOG_FILE
  for gebs in $geb_files; do
    local dir_prefix="$(dirname $gebs)"
    local images="$(cat $gebs | awk -F'</?sidecar>' 'NF>1{print $2}')"
    images+="$(cat $gebs | awk -F'</?filename>' 'NF>1{print $2}')"
    for i in $images; do
      # Prepend the directory of the Google Earth Builder file we are working on.
      sha1sum -b "$dir_prefix/$i" &>> $CHECKSUM_FILE
      echo -n "  Creating checksum for: $dir_prefix/$i...  "
      if [[ $? -eq 0 ]]; then
        echo "OK"
        let "s++"
      else
        echo  "Error"
        let "f++"
        sha1sum -b "$dir_prefix/$i" &>> $LOG_FILE
      fi
    done
  done

  # Check the success/failure of actions above, we can't tolerate failures.
  if [[ "$f" -eq 0 ]]; then
    echo "  Success: Check-summed all images ($s)" \
          | tee -a $LOG_FILE
  else
    echo "  Failure: Unable to check-sum all images ($f)"
    echo "    Refer to $LOG_FILE for details... exiting"
    exit 1
  fi
}

#######################################
# Print usage
# Globals:
#   None
# Arguments:
#   None
# Returns:
#   None
#######################################
function usage {

  cat << EOF
  Usage:
  $0 -s <schema file> -d <directory to process> [ -c ]

  Flags:
  -s The path to the schema file
  -d The top level directory with your data
  -c Create a checksum file for all the images

  Example:
  $0 -s ./ebm_schema.xsd -d ./data/ -c

EOF
}

main () {

  if [[ $# -eq 0 ]]; then
    usage
    exit 1
  fi

  while getopts ":s:d:ch" opt; do
    case $opt in
      s)
        if [[ -e "$OPTARG" ]]; then
          SCHEMA_FILE="$OPTARG"
        else
          echo "Error: $OPTARG does not exist"
          exit 1
        fi
        ;;
      d)
        if [[ -d "$OPTARG" ]]; then
          DATA_DIR="$OPTARG"
        else
          echo "Error: $OPTARG does not exist"
          exit 1
        fi
        ;;
      c)
        CHECKSUM='TRUE'
        ;;
      h)
        usage
        exit 1
        ;;
      \?)
        echo -e "\nInvalid option: -$OPTARG\n"
        usage
        exit 1
        ;;
      :)
        echo -e "\nOption: -$OPTARG requires an argument\n"
        usage
        exit 1
        ;;
    esac
  done

  # Make sure we can write to the directory.
  echo "Process: Trying to create our logfile: $PWD/$LOG_FILE"
  touch $LOG_FILE &> /dev/null
  if [[ $? -gt 0 ]]; then
    echo "  Error: Unable to create our logfile"
  else
    echo "  Success: We have a working logfile!"
  fi

  # Make sure we have the tools we need.
  cmd=''
  echo "Process: Checking to make sure we have our necessary programs" \
        | tee -a $LOG_FILE
  for cmd in $REQ_PROGRAMS; do
    which $cmd &> /dev/null
    if [[ $? -gt 0 ]]; then
      echo "  Error: Required program ($cmd) does not exist" \
            | tee -a $LOG_FILE
      echo "    Refer to $LOG_FILE for details... exiting"
      exit 1
    fi
  done
  echo "  Success: We have all of the necessary programs to run" \
        | tee -a $LOG_FILE

  # Do our real work.
  EBM_FILES="$(locate_ebm_files)"
  validate_data_dir $EBM_FILES
  validate_ebm_against_schema $EBM_FILES
  check_valid_images $EBM_FILES
  if [[ $CHECKSUM == 'TRUE' ]]; then
    checksum_images $EBM_FILES
  fi

  echo "====================================" \
        | tee -a $LOG_FILE
  echo "SUCCESS: We've verified everything." \
        | tee -a $LOG_FILE
  echo "Process logfile: $PWD$LOG_FILE"
  # Only if we were told to create a checksum file.
  if [[ $CHECKSUM == 'TRUE' ]]; then
    echo "Checksum file: $PWD$CHECKSUM_FILE" \
          | tee -a $LOG_FILE
  fi
  echo "====================================" \
        | tee -a $LOG_FILE
}

main $@
