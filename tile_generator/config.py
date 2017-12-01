#!/usr/bin/env python

# tile-generator
#
# Copyright (c) 2015-Present Pivotal Software, Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import, division, print_function#, unicode_literals
import base64
import copy
import cerberus
import os.path
import sys
import yaml
import re
import requests
from . import package_definitions
from . import template

CONFIG_FILE = "tile.yml"
HISTORY_FILE = "tile-history.yml"

# The Config object describes exactly what the Tile Generator is going to generate.
# It starts with a minimal configuration passed in as keyword arguments or read
# from tile.yml, then is gradually transformed into a complete configuration
# through the following phases:
#
# Validate Config - Ensure that all mandatory fields are present, and that any values
# provided meet the constraints for that specific property
#
# Add Defaults - Completes the configuration by inserting defaults for any properties
# not specified in tile.yml. Doing this here allows the remainder of the code to
# safely assume presence of properties (i.e. use config['property'])
#
# Upgrade - Maintains backward compatibility for deprecated tile.yml syntax by
# translating it into currently supported syntax. Doing so here allows us to only
# handle new syntax in the rest of the code, while still maintaining backward
# compatibility
#
# Process Packages - Normalizes all package descriptions and sorts them into the
# appropriate bosh releases depending on their types
#
# Add Dependencies - Add all auto-dependencies for the packages and releases
#
# Normalize File Lists - Packages specify the files they use in many different
# ways depending on the package type. We normalize all these so that the rest of
# the code can rely on a single format
#
# Normalize Jobs - Ensure that job type, template, and properties are set for
# every job

# package_types = {
# 	'app':               { 'flags': [ 'is_cf', 'requires_cf_cli', 'is_app' ] },
# 	'app-broker':        { 'flags': [ 'is_cf', 'requires_cf_cli', 'is_app', 'is_broker', 'is_broker_app' ] },
# 	'external-broker':   { 'flags': [ 'is_cf', 'requires_cf_cli', 'is_broker', 'is_external_broker' ] },
# 	'buildpack':         { 'flags': [ 'is_cf', 'requires_cf_cli', 'is_buildpack' ] },
# 	'decorator':         { 'flags': [ 'is_cf', 'requires_cf_cli', 'requires_meta_buildpack', 'is_buildpack', 'is_decorator' ] },
# 	'docker-bosh':       { 'flags': [ 'requires_docker_bosh', 'is_docker_bosh', 'is_docker' ] },
# 	'docker-app':        { 'flags': [ 'is_cf', 'requires_cf_cli', 'is_app', 'is_docker_app', 'is_docker' ] },
# 	'docker-app-broker': { 'flags': [ 'is_cf', 'requires_cf_cli', 'is_app', 'is_broker', 'is_broker_app', 'is_docker_app', 'is_docker' ] },
# 	'blob':              { 'flags': [ 'is_cf', 'is_blob' ] },
# 	'bosh-release':      { 'flags': [ 'is_bosh_release' ] },
# }

# Inspired by https://gist.github.com/angstwad/bf22d1822c38a92ec0a9
def merge_dict(dct, merge_dct):
	for k, v in merge_dct.iteritems():
		if k in dct and isinstance(dct[k], dict) and isinstance(merge_dct[k], dict):
			merge_dict(dct[k], merge_dct[k])
		else:
			dct[k] = copy.deepcopy(merge_dct[k])

				
class Config(dict):

	def __init__(self, *arg, **kw):
		super(Config, self).__init__(*arg, **kw)

		class ConfigValidator(cerberus.Validator):
			def validate(self, document, schema=None, update=False, normalize=True):
				validated = super(ConfigValidator, self).validate(document, schema, update, normalize)
				if not validated:
					print(document.get('name'), '-> Failed to validate:', self.errors, file=sys.stderr)
					# TODO: remove the sys.exit (everywhere!) and raise instead
					sys.exit(1)
				return self.document

		self._validator = ConfigValidator()
		# This should really not be set but because we don't have the full
		# list of options in the schema it has to be set to pass
		self._validator.allow_unknown = True

		self._package_defs = dict()
		# Nasty way of mapping package types to the relevant classes
		# reall should be explictly importing them
		for k, v in package_definitions.__dict__.items():
			if k.startswith('Package'):
				self._package_defs[v.package_type] = v

		self.tile_metadata = {
			'minimum_version_for_upgrade': '0.0.1',
			'rank': 1,
			'serial': True,
		}

	def read(self):
		self.read_config()
		self.read_history()
		self.transform()
		return self

	def read_config(self):
		try:
			with open(CONFIG_FILE) as config_file:
				self.update(read_yaml(config_file))
		except IOError as e:
			print('Not a tile repository. Use "tile init" in the root of your repository to create one.', file=sys.stderr)
			sys.exit(1)

	def read_history(self):
		try:
			with open(HISTORY_FILE) as history_file:
				self['history'] = read_yaml(history_file)
		except IOError as e:
			self['history'] = {}

	def transform(self):
		self.validate()
		# self.add_defaults()
		self.upgrade()
		# self.process_name()
		# self.process_label()
		# self.process_description()
		# self.process_icon_file()
		# self.process_metadata_version()
		# self.process_packages()
		# self.add_dependencies()
		# self.normalize_file_lists()
		# self.set_package_properties()
		self.normalize_jobs()

	def _validate_base_config(self):
		def base64_img(image):
			try:
				with open(image, 'rb') as f:
					return base64.b64encode(f.read())
			except Exception as e:
				print('tile.yml property "icon_file" must be a path to an image file', file=sys.stderr)
				sys.exit(1)

		schema = {
			'name': {'type': 'string', 'required': True, 'regex': '[a-z][a-z0-9]*(-[a-z0-9]+)*$'},
			'label': {'type': 'string', 'required': True},
			'description': {'type': 'string', 'required': True},
			'icon_file': {'type': 'string', 'required': True, 'coerce': base64_img},
			'metadata_version': {'type': 'number', 'default': 1.8},
			'stemcell_criteria': {'type': 'dict', 'default': self.default_stemcell(), 'schema': {
				'os': {'type': 'string'}, 'version': {'type': 'string'}}},
			'all_properties': {'type': 'list', 'default': []},
			'org': {'type': 'string', 'default_setter': lambda doc: doc['name'] + '-org'},
			'space': {'type': 'string', 'default_setter': lambda doc: doc['name'] + '-space'},
			'apply_open_security_group': {'type': 'boolean', 'default': False},
			'allow_paid_service_plans': {'type': 'boolean', 'default': False},
			'compilation_vm_disk_size': {'type': 'number', 'default': 10240},
			'purge_service_brokers': {'type': 'boolean', 'default': True},
			'forms': {'type': 'list', 'default': [], 'schema': {
				'properties': {'type': 'list', 'default': [], 'schema': {
					'configurable': {'type': 'boolean', 'default': True}}}}},
			'service_plan_forms': {'type': 'list', 'default': [], 'schema': {
				'variable_name': {'type': 'string', 'default_setter': lambda doc: doc['name'].upper()}}},
			'packages': {'type': 'list', 'schema': {
				'type': 'dict', 'schema': {
					# Rename `type` in packages to `package-type` to not trip up cerberus
					'type': {'rename': 'package-type'}}}},
		}


		self.update(self._validator.validate(self, schema))


	def _validate_package(self, package):
		package_schema = self._get_package_def(package).schema()
		package.update(self._validator.validate(package, package_schema))

	def _apply_package_flags(self, config_obj, package):
		package_flags = self._get_package_def(package).flags
		for flag in package_flags:
			flag.generate_release(config_obj, package)

	def _nomalize_package_file_lists(self, package):
		self._get_package_def(package).normalize_file_lists(package)

	def _get_package_def(self, package):
		package_def = self._package_defs.get(package.get('package-type'))
		if not package_def:
			print('package', package.get('name'), 'has invalid type', package.get('package-type'), file=sys.stderr)
			print('valid types are:', ', '.join(self._package_defs.keys()), file=sys.stderr)
			sys.exit(1)
		return package_def

	def validate(self):
		self._validate_base_config()

		# This could be handled in the base config schema with a `oneof` 
		# for `packages` however errors are not very human readable
		for package in self.get('packages', []):
			self._validate_package(package)
			self._apply_package_flags(self, package)
			self._nomalize_package_file_lists(package)

		# TODO: 
		# self['all_properties'] += properties
		# for form in self.get('forms', []):
		# 	properties = form.get('properties', [])
		# 	for property in properties:
		# 		if 'configurable' not in property:
		# 			property['configurable'] = True
		# 	self['all_properties'] += properties

		# TODO: wtf is going on?
		# for property in self['all_properties']:
		# 	property['name'] = property['name'].lower().replace('-','_')
		# 	default = property.get('default', property.pop('value', None)) # NOTE this intentionally removes property['value']
		# 	if default is not None:
		# 		property['default'] = default
		# 	property['configurable'] = property.get('configurable', False)
		# 	property['optional'] = property.get('optional', False)

		#This is for all packages
		# package['name'] = package['name'].lower().replace('-','_')


		#THis is for bosh_release packages
		#job['varname'] = job['name'].lower().replace('-','_')
		#job['is_static'] = job.get('static_ip', 0) > 0

		

		

		

		# TODO: figure out how to do this more nicely
		self.tile_metadata['name'] = self['name']
		self.tile_metadata['label'] = self['label']
		self.tile_metadata['description'] = self['description']
		self.tile_metadata['icon_image'] = self['icon_file']
		self.tile_metadata['metadata_version'] = str(self['metadata_version'])

		


		# class CustomValidator(cerberus.Validator):
		# 	# Create type validatorx to be a more versatile version of
		# 	# the included type validator which does not pass self.
		# 	def _validate_validatorx(self, validator, field, value):
		# 		""" {'oneof': [
		# 						{'type': 'callable'},
		# 						{'type': 'list',
		# 						 'schema': {'oneof': [{'type': 'callable'},
		# 																	{'type': 'string'}]}},
		# 						{'type': 'string'}
		# 						]} """
		# 		if isinstance(validator, cerberus.validator._str_type):
		# 			validator = self.__get_rule_handler('validator', validator)
		# 			validator(self, field, value)
		# 		elif isinstance(validator, cerberus.validator.Iterable):
		# 			for v in validator:
		# 				self._validate_validator(v, self, field, value)
		# 		else:
		# 			validator(self, field, value, self._error)

		# def _document_path_walker(document, path, walk_up, field):
		# 	path = path[:len(path) - walk_up]
		# 	walk = document
		# 	for k in path:
		# 		walk = walk[k]
		# 	return walk.get(field)

		# def not_same_as_pkg_name(self, field, value, error):
		# 	package_name = _document_path_walker(self.root_document, self.document_path, 1, 'name')
		# 	if value == package_name:
		# 		error(field, 'duplicate bosh release', package_name, 'in configuration')

		
			# @classmethod
			# def generate_release(self, package):
			# 	if package.get('is_bosh_release'):
			# 		release_name = package['name']
			# 		release = package
			# 		if self.get('releases', {}).get(release_name):
			# 			print('duplicate bosh release', release_name, 'in configuration', file=sys.stderr)
			# 			sys.exit(1)
			# 	else:
			# 		release_name = self['name']
			# 		default_release = {
			# 				'name': release_name,
			# 				'packages': [],
			# 				'jobs': [] }
			# 		release = self.get('releases', {}).get(release_name, default_release)
			# 		release['packages'] = release.get('packages', []) + [ package ]

			# 	self['releases'][release_name] = release


		

				





		# validname = re.compile('[a-z][a-z0-9]*(-[a-z0-9]+)*$')
		# for package in self.get('packages', []):
		# 	try:
		# 		if validname.match(package['name']) is None:
		# 			print('invalid package name:', package['name'], file=sys.stderr)
		# 			print('package name must start with a letter, be all lower-case letters or numbers, with words optionally seperated by hyphens', file=sys.stderr)
		# 			sys.exit(1)
		# 		if package['type'] not in package_types:
		# 			print('package', package['name'], 'has invalid type', package['type'], file=sys.stderr)
		# 			print('valid types are:', ', '.join([ t for t in package_types]), file=sys.stderr)
		# 			sys.exit(1)
		# 		package['name'] = package['name'].lower().replace('-','_')
		# 		if package['type'] == 'app' or package['type'] == 'app-broker' :
		# 			if package['manifest']['buildpack'] is None:
		# 				print('buildpack required for package '+ package['name'])
		# 				sys.exit(1)
		# 			if package['manifest'].get('random-route'):
		# 				print('Illegal manifest option in package', package['name'] + ': random-route is not supported', file=sys.stderr)
		# 				sys.exit(1)
		# 		if package['type'] == 'docker-bosh' and not package.get('docker_images', []):
		# 			print('docker-bosh package', package['name'], 'must specify docker_images', file=sys.stderr)
		# 			sys.exit(1)
		# 		if package['type'] == 'docker-bosh' and package.get('routes') is not None:
		# 			for route in package.get('routes'):
		# 				prefix = route.get('prefix')
		# 				port = route.get('port')
		# 				if prefix is None or len(prefix) == 0:
		# 					print('docker-bosh routes must have a "prefix"')
		# 					sys.exit(1)
		# 				if port is None:
		# 					print('docker-bosh routes must have a "port"')
		# 					sys.exit(1)
		# 		if package['type'] == 'docker-bosh' and not package.get('manifest'):
		# 				print('docker-bosh requires a manifest')
		# 				sys.exit(1)
		# 		if package['type'] == 'docker-bosh':
		# 			try:
		# 				manifest = yaml.safe_load(package.get('manifest'))
		# 			except:
		# 				print('docker-bosh manifest must be valid yaml')
		# 				sys.exit(1)
		# 			valid_name_pattern = r'^[a-z][a-zA-Z0-9_]*$'
		# 			for container in manifest.get('containers'):
		# 				container_name = container.get('name', '')
		# 				if not re.match(valid_name_pattern, container_name):
		# 					print("docker-bosh container names must be valid shell identifiers. Found invalid: {}".format(container_name))
		# 					sys.exit(1)
		# 		if package['type'] == 'bosh-release':
		# 			for job in package.get('jobs', []):
		# 				job['varname'] = job['name'].lower().replace('-','_')
		# 				job['is_static'] = job.get('static_ip', 0) > 0
		# 	except KeyError as e:
		# 		if str(e) == '\'name\'':
		# 			print('package is missing mandatory property', e, file=sys.stderr)
		# 		else:
		# 			print('package', package['name'], 'is missing mandatory property', e, file=sys.stderr)
		# 		sys.exit(1)

	# def add_defaults(self):
	# 	self['metadata_version'] = self.get('metadata_version', 1.8)
	# 	# Note: tile.py uses self['stemcell_criteria']
	# 	self['stemcell_criteria'] = self.tile_metadata['stemcell_criteria'] = self.default_stemcell()
	# 	self['all_properties'] = self.get('properties', [])
	# 	self['org'] = self.get('org', None) or self['name'] + '-org'
	# 	self['space'] = self.get('space', None) or self['name'] + '-space'
	# 	self['apply_open_security_group'] = self.get('apply_open_security_group', False)
	# 	self['allow_paid_service_plans'] = self.get('allow_paid_service_plans', False)
	# 	self['compilation_vm_disk_size'] = 10240
	# 	self['purge_service_brokers'] = self.get('purge_service_brokers', True)
	# 	for form in self.get('forms', []):
	# 		properties = form.get('properties', [])
	# 		for property in properties:
	# 			if 'configurable' not in property:
	# 				property['configurable'] = True
	# 		self['all_properties'] += properties
	# 	for property in self['all_properties']:
	# 		property['name'] = property['name'].lower().replace('-','_')
	# 		default = property.get('default', property.pop('value', None)) # NOTE this intentionally removes property['value']
	# 		if default is not None:
	# 			property['default'] = default
	# 		property['configurable'] = property.get('configurable', False)
	# 		property['optional'] = property.get('optional', False)
	# 	for package in self.get('packages', []):
	# 		if package['type'] == 'docker-bosh':
	# 			manifest = package['manifest']
	# 			if isinstance(manifest, str):
	# 				package['manifest'] = yaml.safe_load(manifest)
	# 			for container in package['manifest']['containers']:
	# 				envfile = container.get('env_file', [])
	# 				envfile.append('/var/vcap/jobs/docker-bosh-{}/bin/opsmgr.env'.format(package['name']))
	# 				container['env_file'] = envfile
	# 	for form in self.get('service_plan_forms', []):
	# 		form['variable_name'] = form.get('variable_name', form['name'].upper())

	def default_stemcell(self):
		stemcell_criteria = self.get('stemcell_criteria', {})
		stemcell_criteria['os'] = stemcell_criteria.get('os', 'ubuntu-trusty')
		stemcell_criteria['version'] = stemcell_criteria.get('version', self.latest_stemcell(stemcell_criteria['os']))
		return stemcell_criteria

	def latest_stemcell(self, os):
		if os == 'ubuntu-trusty':
			headers = { 'Accept': 'application/json' }
			response = requests.get('https://network.pivotal.io/api/v2/products/stemcells/releases', headers=headers)
			response.raise_for_status()
			releases = response.json()['releases']
			versions = [r['version'] for r in releases]
			latest_major = sorted(versions)[-1].split('.')[0]
			return latest_major
		return None # TODO - Look for latest on bosh.io for given os

	# def process_name(self):
	# 	if not 'name' in self:
	# 		print('tile.yml is missing mandatory property "name"', file=sys.stderr)
	# 		sys.exit(1)
	# 	validname = re.compile('[a-z][a-z0-9]*(-[a-z0-9]+)*$')
	# 	if validname.match(self['name']) is None:
	# 		print('invalid product name:', self['name'], file=sys.stderr)
	# 		print('product name must start with a letter, be all lower-case letters or numbers, with words optionally seperated by hyphens', file=sys.stderr)
	# 		sys.exit(1)
	# 	self.tile_metadata['name'] = self['name']

	# def process_label(self):
	# 	if not 'label' in self:
	# 		print('tile.yml is missing mandatory property "label"', file=sys.stderr)
	# 		sys.exit(1)
	# 	self.tile_metadata['label'] = self['label']

	# def process_description(self):
	# 	if not 'description' in self:
	# 		print('tile.yml is missing mandatory property "description"', file=sys.stderr)
	# 		sys.exit(1)
	# 	self.tile_metadata['description'] = self['description']

	# def process_icon_file(self):
	# 	if not 'icon_file' in self:
	# 		print('tile.yml is missing mandatory property "icon_file"', file=sys.stderr)
	# 		sys.exit(1)
	# 	icon_file = self['icon_file']
	# 	if not (icon_file and os.path.isfile(icon_file)):
	# 		print('tile.yml property "icon_file" must be a path to an image file', file=sys.stderr)
	# 		sys.exit(1)
	# 	with open(icon_file, 'rb') as f:
	# 		self.tile_metadata['icon_image'] = base64.b64encode(f.read())

	# def process_metadata_version(self):
	# 	self.tile_metadata['metadata_version'] = str(self['metadata_version'])

	# TODO: Should be using cerberus. Un-spaghetii-ize this!
	# def process_packages(self):
	# 	import os; os.chdir('/tmp')
	# 	import ipdb; ipdb.set_trace()
	# 	for package in self.get('packages', []):
	# 		typename = package['type']
	# 		typedef = package_types[typename]
	# 		flags = typedef.get('flags', [])
	# 		# jobs = typedef.get('jobs', [])
	# 		# for flag in flags:
	# 		# 	package[flag] = True
	# 		release = self.release_for_package(package)
	# 		if package.get('is_cf', False):
	# 			release['is_cf'] = True
	# 			release['requires_cf_cli'] = True
	# 		if package.get('is_docker_bosh', False):
	# 			self['requires_docker_bosh'] = True
	# 			release['requires_docker_bosh'] = True
	# 			release['jobs'] += [{
	# 				'name': 'docker-bosh-' + package['name'],
	# 				'template': 'docker-bosh',
	# 				'package': package
	# 			}]
	# 		if package.get('is_decorator', False):
	# 			release['requires_meta_buildpack'] = True
	# 		if 'is_app' in flags:
	# 			for link_type, link in package.get('consumes', {}).iteritems():
	# 				release['consumes'] = release.get('consumes', {})
	# 				release['consumes'][link_type] = link
	# 				if 'deployment' in link:
	# 					release['consumes_cross_deployment'] = release.get('consumes_cross_deployment', {})
	# 					release['consumes_cross_deployment'][link_type] = link
	# 			manifest = package.get('manifest', { 'name': package['name'] })
	# 			package['app_manifest'] = manifest
	# 			if not 'is_docker' in flags:
	# 				self.update_compilation_vm_disk_size(manifest)

	# def normalize_file_lists(self):
	# 	for package in self.get('packages', []):
	# 		if package.get('is_bosh_release', False):
	# 			continue
	# 		files = package.get('files', [])
	# 		path = package.get('path', None)
	# 		if path is not None:
	# 			files += [ { 'path': path } ]
	# 			package['path'] = os.path.basename(path)
	# 		manifest = package.get('manifest', {})
	# 		manifest_path = manifest.get('path', None)
	# 		if manifest_path is not None:
	# 			files += [ { 'path': manifest_path } ]
	# 			package['manifest']['path'] = os.path.basename(manifest_path)
	# 		for docker_image in package.get('docker_images', []):
	# 			filename = docker_image.lower().replace('/','-').replace(':','-') + '.tgz'
	# 			files += [ { 'path': 'docker:' + docker_image, 'name': filename } ]
	# 		for file in files:
	# 			file['name'] = file.get('name', os.path.basename(file['path']))
	# 		package['files'] = files

	# def set_package_properties(self):
	# 	for package in self.get('packages', []):
	# 		packagename = package['name']
	# 		properties = {'name': packagename}
	# 		if package.get('is_external_broker'):
	# 			properties.update({
	# 				'url': '(( .properties.{}_url.value ))'.format(packagename),
	# 				'user': '(( .properties.{}_user.value ))'.format(packagename),
	# 				'password': '(( .properties.{}_password.value ))'.format(packagename),
	# 			})
	# 		if package.get('is_broker'):
	# 			properties.update({
	# 				'enable_global_access_to_plans': '(( .properties.{}_enable_global_access_to_plans.value ))'.format(packagename),
	# 			})
	# 		if package.get('is_buildpack'):
	# 			properties.update({
	# 				'buildpack_order': '(( .properties.{}_buildpack_order.value ))'.format(packagename),
	# 			})
	# 		if package.get('is_docker_bosh'):
	# 			properties.update({
	# 				'host': '(( .docker-bosh-{}.first_ip ))'.format(packagename),
	# 				'hosts': '(( .docker-bosh-{}.ips ))'.format(packagename),
	# 			})
	# 		if package.get('is_bosh_release'):
	# 			for job in package.get('jobs', []):
	# 				jobname = job['name']
	# 				if job.get('is_static'):
	# 					properties.update({
	# 						job['varname']: {
	# 							'host': '(( .{}.first_ip ))'.format(jobname),
	# 							'hosts': '(( .{}.ips ))'.format(jobname),
	# 						},
	# 					})
	# 		if package.get('is_app'):
	# 			properties.update({
	# 				'app_manifest': package['app_manifest'],
	# 				'auto_services': package.get('auto_services', []),
	# 			})
	# 		package['properties'] = {packagename: properties}

	def normalize_jobs(self):
		for release in self.get('releases', []).values():
			for job in release.get('jobs', []):
				job['type'] = job.get('type', job['name'])
				job['template'] = job.get('template', job['type'])
				job['properties'] = job.get('properties', {})
				job['manifest'] = self.build_job_manifest(job)

	def build_job_manifest(self, job):
		manifest = {
			'domain': '(( ..cf.cloud_controller.system_domain.value ))',
			'app_domains': ['(( ..cf.cloud_controller.apps_domain.value ))'],
			'org': '(( .properties.org.value ))',
			'space': '(( .properties.space.value ))',
			'ssl': {'skip_cert_verify': '(( ..cf.ha_proxy.skip_cert_verify.value ))'},
			'cf': {
				'admin_user': '(( ..cf.uaa.system_services_credentials.identity ))',
				'admin_password': '(( ..cf.uaa.system_services_credentials.password ))',
			},
			'apply_open_security_group': '(( .properties.apply_open_security_group.value ))',
			'allow_paid_service_plans': '(( .properties.allow_paid_service_plans.value ))',
		}
		if job.get('type') == 'deploy-all':
			merge_dict(manifest, {
				'security': {
					'user': '(( .{}.app_credentials.identity ))'.format(job['name']),
					'password': '(( .{}.app_credentials.password ))'.format(job['name']),
				}
			})
		merge_dict(manifest, job['properties'])
		for property in self.get('all_properties', []):
			merge_dict(manifest, template.render_property(property))
		for service_plan_form in self.get('service_plan_forms', []):
			manifest[service_plan_form['name']] = '(( .properties.{}.value ))'.format(service_plan_form['name'])
		for package in self.get('packages', []):
			merge_dict(manifest, package['properties'])
			if job.get('type') == 'deploy-all' and package.get('is_external_broker'):
				merge_dict(manifest, {
					package['name']: {
						'url': '(( .properties.{}_url.value ))'.format(pakage['name']),
						'user': '(( .properties.{}_user.value ))'.format(pakage['name']),
						'password': '(( .properties.{}_password.value ))'.format(pakage['name']),
					}
				})
			elif job.get('type') == 'deploy-all' and package.get('is_broker'):
				merge_dict(manifest, {
					package['name']: {
						'user': '(( .{}.app_credentials.identity ))'.format(job['name']),
						'password': '(( .{}.app_credentials.password ))'.format(job['name']),
					}
				})
		return manifest

	# def release_for_package(self, package):
	# 	release_name = package['name'] if package.get('is_bosh_release', False) else self['name']
	# 	release = self.release_by_name(release_name)
	# 	if package.get('is_bosh_release', False):
	# 		if release is not None:
	# 			print('duplicate bosh release', release_name, 'in configuration', file=sys.stderr)
	# 			sys.exit(1)
	# 		release = package
	# 		self['releases'] = self.get('releases', []) + [ release ]
	# 	else:
	# 		if release is None:
	# 			release = {
	# 				'name': release_name,
	# 				'packages': [],
	# 				'jobs': [] }
	# 			self['releases'] = self.get('releases', []) + [ release ]
	# 		release['packages'] = release.get('packages', []) + [ package ]
	# 	return release

	# def release_by_name(self, name):
	# 	for release in self.get('releases', []):
	# 		if release['name'] == name:
	# 			return release
	# 	return None

	# def add_dependencies(self):
	# 	requires_docker_bosh = False
	# 	requires_meta_buildpack = False
	# 	for release in self.get('releases', []):
	# 		if release.get('requires_docker_bosh', False):
	# 			requires_docker_bosh = True
	# 			release['packages'] += [{
	# 				'name': 'common',
	# 				'files': [{
	# 					'name': 'utils.sh',
	# 					'path': template.path('src/common/utils.sh')
	# 				}],
	# 				'template': 'common',
	# 				'dir': 'src'
	# 			}]
	# 		if release.get('requires_meta_buildpack', False):
	# 			requires_meta_buildpack = True
	# 		if release.get('requires_cf_cli', False):
	# 			release['jobs'] += [{
	# 				'name': 'deploy-all',
	# 				'type': 'deploy-all',
	# 				'lifecycle': 'errand',
	# 				'post_deploy': True
	# 			}]
	# 			release['jobs'] += [{
	# 				'name': 'delete-all',
	# 				'type': 'delete-all',
	# 				'lifecycle': 'errand',
	# 				'pre_delete': True
	# 			}]
	# 			self['post_deploy_errands'] = self.get('post_deploy_errands', []) + [{ 'name': 'deploy-all' }]
	# 			self['pre_delete_errands'] = self.get('pre_delete_errands', []) + [{ 'name': 'delete-all' }]
	# 			release['packages'] += [{
	# 				'name': 'cf_cli',
	# 				'files': [{
	# 					'name': 'cf-linux-amd64.tgz',
	# 					'path': 'http://cli.run.pivotal.io/stable?release=linux64-binary&source=github-rel'
	# 				},{
	# 					'name': 'all_open.json',
	# 					'path': template.path('src/templates/all_open.json')
	# 				}],
	# 				'template': 'cf_cli',
	# 				'dir': 'blobs'
	# 			}]
	# 			self.tile_metadata['requires_product_versions'] = self.get('requires_product_versions', []) + [
	# 				{
	# 					'name': 'cf',
	# 					'version': '>= 1.9'
	# 				}
	# 			]
	# 	if requires_docker_bosh:
	# 		version = None
	# 		version_param = '?v=' + version if version else ''
	# 		self['releases'] += [{
	# 			'name': 'docker-boshrelease',
	# 			'path': 'https://bosh.io/d/github.com/cf-platform-eng/docker-boshrelease' + version_param,
	# 		},{
	# 			'name': 'routing',
	# 			'path': 'https://bosh.io/d/github.com/cloudfoundry-incubator/cf-routing-release',
	# 		}]
	# 	if requires_meta_buildpack:
	# 		self['releases'] += [{
	# 			'name': 'meta-buildpack',
	# 			'path': 'github://cf-platform-eng/meta-buildpack/meta-buildpack.tgz',
	# 			'jobs': [
	# 				{
	# 					'name': 'deploy-meta-buildpack',
	# 					'type': 'deploy-all',
	# 					'lifecycle': 'errand',
	# 					'post_deploy': True
	# 				},
	# 				{
	# 					'name': 'delete-meta-buildpack',
	# 					'type': 'delete-all',
	# 					'lifecycle': 'errand',
	# 					'pre_delete': True
	# 				}
	# 			]
	# 		}]

	def save_history(self):
		with open(HISTORY_FILE, 'wb') as history_file:
			write_yaml(history_file, self['history'])

	def set_verbose(self, verbose=True):
		self['verbose'] = verbose

	def set_sha1(self, sha1=True):
		self['sha1'] = sha1

	def set_cache(self, cache=None):
		if cache is not None:
			cache = os.path.realpath(os.path.expanduser(cache))
			self['docker_cache'] = cache
			self['cache'] = cache

	def upgrade(self):
		# v0.9 specified auto_services as a space-separated string of service names
		for package in self.get('packages', []):
			auto_services = package.get('auto_services', None)
			if auto_services is not None:
				if isinstance(auto_services, str):
					package['auto_services'] = [ { 'name': s } for s in auto_services.split()]
		# v0.9 expected a string manifest for docker-bosh releases
		for package in self.get('packages', []):
			if package.get('type') == 'docker-bosh':
				manifest = package.get('manifest')
				if manifest is not None and isinstance(manifest, str):
					package['manifest'] = yaml.safe_load(manifest)
		# first releases required manifests to be multi-line strings, now we want them to be dicts
		for package in self.get('packages', []):
			manifest = package.get('manifest', None)
			if manifest is not None and type(manifest) is not dict:
				manifest = read_yaml(manifest)
				package['manifest'] = manifest
		# We've deprecated dynamic_service_plans in favor of service_plan_forms,
		# which allow multiple sets of dynamic service plans
		dynamic_service_plans = self.get('dynamic_service_plans', None)
		if dynamic_service_plans is not None:
			print('WARNING - dynamic_service_plans have been deprecated, use service_plan_forms instead\n', file=sys.stderr)
			self['service_plan_forms'] = [{
				'name': 'dynamic_service_plans',
				'variable_name': 'PLANS',
				'label': 'Dynamic Service Plans',
				'description': 'Operator-Defined Service Plans',
				'properties': dynamic_service_plans
			}] + self.get('service_plan_forms', [])
		# We've deprecated configurable_persistence in favor of the more generic auto_services
		for package in self.get('packages', []):
			configurable_persistence = package.get('configurable_persistence', None)
			if configurable_persistence is not None:
				print('ERROR - configurable_persistence has been deprecated, use auto_services instead', file=sys.stderr)
				sys.exit(1)

	def set_version(self, version):
		if version is None:
			version = 'patch'
		history = self.get('history', {})
		prior_version = history.get('version', None)
		if prior_version is not None:
			history['history'] = history.get('history', [])
			history['history'] += [ prior_version ]
		if not is_semver(version):
			semver = history.get('version', '0.0.0')
			if not is_unannotated_semver(semver):
				print('The prior version was', semver, file=sys.stderr)
				print('To auto-increment, the prior version must be in semver format (x.y.z), and must not include a label.', file=sys.stderr)
				sys.exit(1)
			semver = semver.split('.')
			if version == 'patch':
				semver[2] = str(int(semver[2]) + 1)
			elif version == 'minor':
				semver[1] = str(int(semver[1]) + 1)
				semver[2] = '0'
			elif version == 'major':
				semver[0] = str(int(semver[0]) + 1)
				semver[1] = '0'
				semver[2] = '0'
			else:
				print('Argument must specify "patch", "minor", "major", or a valid semver version (x.y.z)', file=sys.stderr)
				sys.exit(1)
			version = '.'.join(semver)
		history['version'] = version
		self['version'] = version
		self.tile_metadata['product_version'] = str(version)

	# def update_compilation_vm_disk_size(self, manifest):
	# 	package_file = manifest.get('path')
	# 	if not isinstance(package_file, basestring) or not os.path.exists(package_file):
	# 		print('Package file "{}" not found! Please check the manifest path in your tile.yml file.'.format(package_file), file=sys.stderr)
	# 		sys.exit(1)
	# 	package_size = os.path.getsize(package_file) // (1024 * 1024) # bytes to megabytes
	# 	self['compilation_vm_disk_size'] = max(self['compilation_vm_disk_size'], 4 * package_size)

def read_yaml(file):
	return yaml.safe_load(file)

def write_yaml(file, data):
	file.write(yaml.safe_dump(data, default_flow_style=False, explicit_start=True))

def is_semver(version):
	valid = re.compile('[0-9]+\\.[0-9]+\\.[0-9]+([\\-+][0-9a-zA-Z]+(\\.[0-9a-zA-Z]+)*)*$')
	return valid.match(version) is not None

def is_unannotated_semver(version):
	valid = re.compile('[0-9]+\\.[0-9]+\\.[0-9]+$')
	return valid.match(version) is not None
