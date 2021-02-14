# Panther is a Cloud-Native SIEM for the Modern Security Team.
# Copyright (C) 2020 Panther Labs Inc
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import boto3    #
import botocore #
import hashlib  #
import json     #
import logging  #
import os       # https://www.tutorialspoint.com/python/os_walk.htm
import re       #
import shutil   #
import sys      #
import tempfile #
import types    #
import zipfile  # https://docs.python.org/3/library/zipfile.html
from typing import Any, Dict, List, Optional, Tuple

from botocore.exceptions import ClientError

layer_sig_name = "panther-layer-sig"
call_list_layers = True
call_remove_layer = False
call_list_buckets = True
call_list_bucket_files = True
print_debug = True

def debuglog():
    if not print_debug:
        return
    print()
    print("DEBUG LOG")
    print()
    print("  layer_bucket_name: %s" % layer_bucket_name())
    print()
#     print("  build_layer:       %r" % call_build_layer)
    print("  list_layers:       %r" % call_list_layers)
    print("  remove_layer:      %r" % call_remove_layer)
    print("  list_buckets:      %r" % call_list_buckets)
    print("  list_bucket_files: %r" % call_list_bucket_files)
    print()

# HELPERS:
# --------------------------------------------------------------------------------

# Removes all items from a directory.
# Will raise an exception if path is not a directory path or any permissions for read, write, and
# exec on the directory are missing
def cleandir(dirpath):
    if not os.path.exists(dirpath):
        raise Exception("cleandir dirpath is not an existing file system path")
    if not os.path.isdir(dirpath):
        raise Exception("cleandir dirpath is not a directory path")
    if not os.access(dirpath, os.R_OK | os.W_OK | os.X_OK):
        raise Exception("cleandir dirpath is missing permissions to read, write, or exec")
    for f in os.listdir(dirpath):
        rmfpath(os.path.join(dirpath, f))
    return dirpath

# check_fmt_libs:
#   checks libs is list of strings
#   sort the list
#   list length > 0
# TODO:
#   dedup (essentially checks for clashing values)
def check_fmt_libs(libs):
    if not isinstance(libs, list):
        raise Exception("check_fmt_libs list is not a list type")
    libs.sort()
    if len(libs) < 1:
        raise Exception("check_fmt_libs list length is 0")
    return libs

# Returns the hash of the libs list.
# This method expects a sorted, formatted valid list of pip libs
# NOTE: this hash is not used for file integrity, Its used for a uid
def hash_libs(libs):
    h = hashlib.new('sha256')
    for mod in libs:
        h.update(mod.encode())
    return h.hexdigest()

# Removes a file or a directory (and it's contents) if either exists at fspath
def rmfpath(fspath):
    if not os.path.exists(fspath):
        return
    if os.path.isfile(fspath):
        os.remove(fspath)
    if os.path.isdir(fspath):
        shutil.rmtree(fspath)

# TODO: Check for .zip extension, existing file, existing source dir
def zip_dir_to_dst(src, target):
    if not os.path.exists(src):
        raise Exception("zip_dir_to_dst src is not an existing file system path")
    if not os.path.isdir(src):
        raise Exception("zip_dir_to_dst src is not a directory path")
    if not os.access(src, os.R_OK | os.W_OK | os.X_OK):
        raise Exception("zip_dir_to_dst src is missing permissions to read, write, or exec")
    rmfpath(target)
    zipf = zipfile.ZipFile(target, 'w', zipfile.ZIP_DEFLATED)
    for root, dirs, files in os.walk(src):
        for file in files:
            fpath = os.path.join(root, file)
            arcname = os.path.relpath(os.path.join(root, file), src)
            zipf.write(fpath, arcname)
    zipf.close()

# Storage Interfacing:
# --------------------------------------------------------------------------------

# Resource Getters
def get_s3_bucket_files(s3, bucket_name):
    bucket = s3.Bucket(bucket_name)
    s3_file_set = list()
    for obj in bucket.objects.all():
        s3_file_set.append(obj.key)
    return s3_file_set
def get_s3_buckets(s3):
    # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html#S3.Client.list_buckets
    response = s3.list_buckets()
    return response["Buckets"]

# List Methods
def list_s3_buckets():
    print("LIST S3 BUCKETS:\n")
    s3 = boto3.client('s3')
    buckets = get_s3_buckets(s3)
    for bucket in buckets:
        print("  %s" % bucket["Name"])
    print("\n  COUNT: %d\n" % len(buckets))
def list_s3_files(bucket_name):
    print("LIST S3 FILES - BUCKET: %s\n" % bucket_name)
    # List files in the bucket named <bucketname>
    s3 = boto3.resource('s3')
    bucket_files = get_s3_bucket_files(s3, bucket_name)
    for bucket_file in bucket_files:
        print("  %s" % bucket_file)
    print("\n  COUNT: %d\n" % len(bucket_files))

# Sourced from https://boto3.amazonaws.com/v1/documentation/api/latest/guide/s3-uploading-files.html
def upload_file(file_name, bucket, object_name=None):
    """Upload a file to an S3 bucket

    :param file_name: File to upload
    :param bucket: Bucket to upload to
    :param object_name: S3 object name. If not specified then file_name is used
    :return: True if file was uploaded, else False
    """
    # If S3 object_name was not specified, use file_name
    if object_name is None:
        object_name = file_name
    # Upload the file
    s3_client = boto3.client('s3')
    try:
        response = s3_client.upload_file(file_name, bucket, object_name)
    except ClientError as e:
        logging.error(e)
        return False
    return True
def rm_s3_file(key, bucket):
    s3 = boto3.resource('s3')
    s3.Object(bucket, key).delete()

# Layer Interfacing
# -------------------------------------------------------------------------------------------------

# Build the layer with the passed libs
def build_layer(libs):
    print("BUILD LAYER:")
    libset = check_fmt_libs(libs)

    # getnativetmpdirpath returns a new directory, cleandir checks permissions, isdir, exists and clean
    src_dir = tempfile.mkdtemp()
    cleandir(src_dir)
    py_src_dir = os.path.join(src_dir, "python")
    os.mkdir(py_src_dir)

    # exec_str is the invoked shell command and is basically
    exec_str = "{} install -t {} --no-cache-dir {}"
    exec_str = exec_str.format("pip3", py_src_dir, " ".join(libset))
    os.system(exec_str)

    # Write the layer signature file
    f = open(os.path.join(src_dir, layer_sig_name), 'w')
    f.write(hash_libs(libset))
    f.close()

    # Temporary path where we zip the layer source
    zip_dst = os.path.join(tempfile.gettempdir(), "layer.zip")
    zip_dir_to_dst(src_dir, zip_dst)
    rmfpath(src_dir)
    return zip_dst

# Retrieves the layer URIS currently available in the remote storage host (s3)
def get_layers():
    bucket_name = layer_bucket_name()
    s3 = boto3.resource('s3')
    return get_s3_bucket_files(s3, bucket_name)

# Checks if the remote storage host (s3) contains a layer for the given hash (layer id / name)
def layer_exists(hashstr):
    return hashstr in get_layers()

# Prints the remote hosted (s3) layers (hash_libs) to stdout
def list_layers():
    print("LIST LAYERS:\n")
    layers = get_layers()
    for layer in layers:
        print("  %s" % layer)
    print("\n  COUNT: %d\n" % len(layers))

# Pushes the layer zip file to the remote storage host (s3)
def push_layer_zip(layer_zip_path):
    print("PUSH LAYER:\n")
    if not os.path.exists(layer_zip_path):
        raise Exception("push_layer layer_zip_path is not an existing file system path")
    if not os.path.isfile(layer_zip_path):
        raise Exception("push_layer_zip layer_zip_path is not a file")
    if not os.access(layer_zip_path, os.R_OK):
        raise Exception("push_layer_zip requires read permissions on layer_zip_path {}".format(layer_zip_path))
    archive = zipfile.ZipFile(layer_zip_path, 'r')
    # Verify the layer signature file is in the package
    if layer_sig_name not in archive.namelist():
        logging.error("push_layer_zip archive is missing the {} hash signature file".format(layer_sig_name))
        return False
    hash = archive.read(layer_sig_name).decode()
    print("  %s" % hash)
    validhash = re.search("[A-Fa-f0-9]{64}", hash)
    if validhash is None:
        logging.error("push_layer_zip {} file content is not a valid sha256 hash")
        return
    s3 = boto3.client('s3')
    with open(layer_zip_path, "rb") as f:
        s3.upload_fileobj(f, layer_bucket_name(), hash)

# Deletes a layer from the remote storage host (s3)
def remove_layer(layerhash):
    print("REMOVE LAYER: %s\n" % layerhash)
    rm_s3_file(layerhash, layer_bucket_name())
    print()

# This method makes no assumptions about the validity of the libs parameter.
def handle_layer_request(libs):
    print("HANDLE LAYER REQUEST:\n")
    libset = check_fmt_libs(libs)
    hash = hash_libs(libs)
    if not layer_exists(hash):
        print("BUILDING NEW LAYer {}".format(hash))
        layer_zip_path = build_layer(libset)
        push_layer_zip(layer_zip_path)
        rmfpath(layer_zip_path)
    else:
        print("  HASH:\n")
        print("  %s\n" % hash)
        print("  LAYER ALREADY UPLOADED")
    print()

# TEMPORARY METHODS?
# --------------------------------------------------------------------------------

# BUCKET:
def layer_bucket_name():
    return os.getenv('BUCKET')

#  pylint: disable=unsubscriptable-object
def lambda_handler(event: Dict[str, Any], unused_context: Any) -> Optional[Dict[str, Any]]:
    """Entry point for the Lambda"""
    libs = check_fmt_libs(event["libs"])
    debuglog()

    try:
         if call_list_buckets:
             list_s3_buckets()
         if call_list_bucket_files:
             list_s3_files(layer_bucket_name())
         if call_list_layers:
             list_layers()
         # if call_remove_layer:
        #     remove_layer("00f4e0dae31b9fd0483542a6bc9c21cbd46f50bcde5ed832a117e8ad78519b13")
    except:
      print("Unexpected error:", sys.exc_info()[0])
      raise

    hash = hash_libs(libs)
    if not layer_exists(hash):
        print("BUILDING NEW LAYer {}".format(hash))
        layer_zip_path = build_layer(libset)
        push_layer_zip(layer_zip_path)
        rmfpath(layer_zip_path)
    else:
        print("  HASH:\n")
        print("  %s\n" % hash)
        print("  LAYER ALREADY UPLOADED")
    print()

# [ERROR] ClientError: An error occurred (AccessDenied) when calling the ListObjects operation: Access Denied
# call_build_layer = False
