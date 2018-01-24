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


# Inspired by https://gist.github.com/angstwad/bf22d1822c38a92ec0a9
def merge_dict(dct, merge_dct):
	for k, v in merge_dct.iteritems():
		if k in dct and isinstance(dct[k], dict) and isinstance(merge_dct[k], dict):
			merge_dict(dct[k], merge_dct[k])
		else:
			dct[k] = copy.deepcopy(merge_dct[k])

# Pulling out from Config._validate to global for easy testing
def _base64_img(image):
			try:
				with open(image, 'rb') as f:
					return base64.b64encode(f.read())
			except Exception as e:
				print('tile.yml property "icon_file" must be a path to an image file', file=sys.stderr)
				sys.exit(1)


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
		self.upgrade()
		self.normalize_jobs()

	def _validate_base_config(self):
		schema = {
			'name': {'type': 'string', 'required': True, 'regex': '[a-z][a-z0-9]*(-[a-z0-9]+)*$'},
			'service_broker': {'type': 'boolean', 'required': False, 'default': False},
			'label': {'type': 'string', 'required': True},
			'description': {'type': 'string', 'required': True},
			'icon_file': {'type': 'string', 'required': True, 'coerce': _base64_img},
			'metadata_version': {'type': 'number', 'default': 1.8},
			'stemcell_criteria': {'type': 'dict', 'default': self.default_stemcell(), 'schema': {
				'os': {'type': 'string'}, 'version': {'type': 'string'}}},
			'all_properties': {'type': 'list', 'default_setter': lambda doc: doc.get('properties', [])},
			'org': {'type': 'string', 'default_setter': lambda doc: doc['name'] + '-org'},
			'space': {'type': 'string', 'default_setter': lambda doc: doc['name'] + '-space'},
			'apply_open_security_group': {'type': 'boolean', 'default': False},
			'allow_paid_service_plans': {'type': 'boolean', 'default': False},
			'compilation_vm_disk_size': {'type': 'number', 'default': 10240},
			'purge_service_brokers': {'type': 'boolean', 'default': True},
			'forms': {'type': 'list', 'default': [], 'schema': {
				'type': 'dict', 'default': {}, 'schema': {
					'properties': {'type': 'list', 'default': [], 'schema': {
						'type': 'dict', 'default': {}, 'schema': {
							'configurable': {'type': 'boolean', 'default': True}}}}}}},
			'service_plan_forms': {'type': 'list', 'default': [], 'schema': {
				'type': 'dict', 'default': {}, 'schema': {
					'variable_name': {'type': 'string', 'required': True, 'default_setter': lambda doc: doc['name'].upper()}}}},
			'packages': {'type': 'list', 'schema': {
				'type': 'dict', 'schema': {
					'name': {'type': 'string', 'required': True, 'regex': '[a-z][a-z0-9]*(-[a-z0-9]+)*$'},
					# Rename `type` in packages to `package-type` to not trip up cerberus
					'type': {'rename': 'package-type'}}}},
			'runtime_configs': {'type': 'list', 'schema': {
				'type': 'dict', 'schema': {
					'name': {'type': 'string', 'required': True, 'regex': '[a-zA-Z][a-zA-Z0-9_-]*$'},
					'runtime_config': {'required': True, 'type': 'dict', 'schema': {
						'releases': {'required': True, 'type': 'list', 'schema': {
							'type': 'dict', 'schema': {
								'name': {'type': 'string', 'required': True, 'regex': '[a-zA-Z][a-zA-Z0-9_-]*$'},
								'version': {'type': 'number', 'required': True},
						}}},
						'addons': {'required': True, 'type': 'list', 'schema': {
							'type': 'dict', 'schema': {
								'name': {'type': 'string', 'required': True, 'regex': '[a-zA-Z][a-zA-Z0-9_-]*$'},
								'properties': {'type': 'dict'},
								'jobs': {'required': True, 'type': 'list', 'schema': {
									'type': 'dict', 'schema': {
										'name': {'type': 'string', 'required': True, 'regex': '[a-zA-Z][a-zA-Z0-9_-]*$'},
										'release': {'type': 'string', 'required': True}
								}}}
						}}}
					}}
			}}}
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

		# TODO: This should be handled differently
		for form in self.get('forms', []):
			properties = form.get('properties', [])
			self['all_properties'] += properties

		# This could be handled in the base config schema with a `oneof`
		# for `packages` however errors are not very human readable
		for package in self.get('packages', []):
			self._validate_package(package)
			self._apply_package_flags(self, package)
			self._nomalize_package_file_lists(package)


		# TODO: wtf is going on here and why?
		for property in self['all_properties']:
			property['name'] = property['name'].lower().replace('-','_')
			default = property.get('default', property.pop('value', None)) # NOTE this intentionally removes property['value']
			if default is not None:
				property['default'] = default
			property['configurable'] = property.get('configurable', False)
			property['optional'] = property.get('optional', False)

		# TODO: figure out how to do this more nicely
		self.tile_metadata['name'] = self['name']
		self.tile_metadata['label'] = self['label']
		self.tile_metadata['description'] = self['description']
		self.tile_metadata['icon_image'] = self['icon_file']
		self.tile_metadata['metadata_version'] = str(self['metadata_version'])
		# Note: tile.py uses self['stemcell_criteria']
		self.tile_metadata['stemcell_criteria'] = self['stemcell_criteria']
		self.tile_metadata['service_broker'] = self['service_broker']

		# TODO: this probably should also be handled differently
		for runtime_conf in self.get('runtime_configs', {}):
			if runtime_conf.get('runtime_config'):
				runtime_conf['runtime_config'] = yaml.dump(runtime_conf['runtime_config'], default_flow_style=False)
		self.tile_metadata['runtime_configs'] = self.get('runtime_configs')


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

	def normalize_jobs(self):
		for release in self.get('releases', {}).values():
			for job in release.get('jobs', []):
				job['type'] = job.get('type', job['name'])
				job['template'] = job.get('template', job['type'])
				job['properties'] = job.get('properties', {})
				job['manifest'] = self.build_job_manifest(job)

	def build_job_manifest(self, job):
		# TODO: This whole thing needs to be changed to new world order
		# This should not have to happen
		from .package_flags import ExternalBroker, Broker

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
			package_flags = self._get_package_def(package).flags
			merge_dict(manifest, package['properties'])
			if job.get('type') == 'deploy-all' and ExternalBroker in package_flags:
				merge_dict(manifest, {
					package['name']: {
						'url': '(( .properties.{}_url.value ))'.format(pakage['name']),
						'user': '(( .properties.{}_user.value ))'.format(pakage['name']),
						'password': '(( .properties.{}_password.value ))'.format(pakage['name']),
					}
				})
			elif job.get('type') == 'deploy-all' and Broker in package_flags:
				merge_dict(manifest, {
					package['name']: {
						'user': '(( .{}.app_credentials.identity ))'.format(job['name']),
						'password': '(( .{}.app_credentials.password ))'.format(job['name']),
					}
				})
		return manifest

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
