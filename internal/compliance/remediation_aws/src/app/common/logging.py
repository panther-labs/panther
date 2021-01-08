# Panther is a Cloud-Native SIEM for the Modern Security Team.
# Copyright (C) 2021 Panther Labs Inc
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

import logging
import os


def get_logger() -> logging.Logger:
    """Utility method to get a properly configured logger instance"""

    level = os.environ.get('LOGGING_LEVEL', 'INFO')

    logging.basicConfig(format='[%(levelname)s %(asctime)s (%(name)s:%(lineno)d)]: %(message)s')
    logger = logging.getLogger()

    try:
        logger.setLevel(level.upper())
    except (TypeError, ValueError) as err:
        logger.setLevel('INFO')
        logger.error('Defaulting to INFO logging: %s', str(err))

    return logger
