# Copyright 2020-2021 Canonical Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# For further info, check https://github.com/canonical/charmcraft

"""Infrastructure for the 'pack' command."""

import logging
import os
import pathlib
import zipfile

from charmcraft.cmdbase import BaseCommand, CommandError
from charmcraft.utils import load_yaml

logger = logging.getLogger(__name__)

# the minimum set of files in a bundle
MANDATORY_FILES = {'bundle.yaml'}


def build_zip(zippath, basedir):
    """Build the final file.

    Note we convert all paths to str to support Python 3.5.
    """
    logger.debug("Building the zip file")
    zipfh = zipfile.ZipFile(zipname, 'w', zipfile.ZIP_DEFLATED)

    # FIXME: what about symlinks????
    basedir_str = str(basedir)  # os.walk does not support pathlib in 3.5
    for dirpath, dirnames, filenames in os.walk(basedir_str, followlinks=True):
        dirpath = pathlib.Path(dirpath)
        for filename in filenames:
            filepath = dirpath / filename
            zipfh.write(str(filepath), str(filepath.relative_to(basedir)))
    zipfh.close()


_overview = """
Build the bundle and package it as a zip archive.

You can `juju deploy` the bundle .zip file or upload it to
the store (see the "upload" command).
"""


class PackCommand(BaseCommand):
    """Build the bundle or the charm.

    Eventually this command will also support charms, but for now it will work only
    on bundles.
    """

    name = 'pack'
    help_msg = "Build the bundle"
    overview = _overview
    needs_config = True

    def run(self, parsed_args):
        """Run the command."""
        # get the config files
        bundle_filepath = self.config.project.dirpath / 'bundle.yaml'
        bundle_config = load_yaml(bundle_filepath)

        # this is new to this code
        from craft_parts import plugins, LifecycleManager, Step  # FIXME: fix this, but getting stuff really from an installed project, not copied dir
        from craft_parts.plugins.v2.dump import DumpPlugin
        plugins.register({"bundle": DumpPlugin})
        dirpath = self.config.project.dirpath

        # these are all verifications that are agnostic to LifecycleMAnager
        if bundle_config is None:
            raise CommandError(
                "Missing or invalid main bundle file: '{}'.".format(bundle_filepath))
        bundle_name = bundle_config.get('name')
        if not bundle_name:
            raise CommandError(
                "Invalid bundle config; missing a 'name' field indicating the bundle's name in "
                "file '{}'.".format(bundle_filepath))

        # so far 'pack' works for bundles only (later this will operate also on charms)
        if self.config.type != 'bundle':
            raise CommandError(
                "Bad config: 'type' field in charmcraft.yaml must be 'bundle' for this command.")

        # add mandatory files
        parts = self.config.parts.copy()
        parts.setdefault('bundle', {}).setdefault('prime', []).extend(MANDATORY_FILES)

        # pack everything (new code!!!)
        lf = LifecycleManager(
            {'parts': parts}, application_name="charmcraft", project_name="crazy-prototype")
        lf.update()
        actions = lf.plan(Step.PRIME)  # , part_names)

        logger.debug("Planned actions: %s", actions)
        with lf.execution_context() as ctx:
            for action in actions:
                logger.debug("Executing action %s", action)
                ctx.execute(action)

        zipname = self.config.project.dirpath / (bundle_name + '.zip')
        # FIXME: we should do better than harcoding "./prime"
        basedir = pathlib.Path('./prime')
        build_zip(zipname, basedir)
        logger.info("Created '%s'.", zipname)
