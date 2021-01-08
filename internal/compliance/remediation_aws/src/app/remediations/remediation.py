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

from typing import Any, Dict, Type

from ..common.exceptions import RemediationDoesNotExist
from .remediation_base import RemediationBase


class Remediation:
    """Class to be used as a decorator to register all remediation subclasses"""
    _remediations: Dict[str, Type[RemediationBase]] = {}  # Maps remediationID to subclass

    @staticmethod
    def __new__(cls: Type, remediation: Type[RemediationBase]) -> Any:
        remediation_id = remediation.remediation_id()
        cls._remediations[remediation_id] = remediation
        return remediation

    @classmethod
    def get(cls, remediation_id: str) -> Type[RemediationBase]:
        """Return the proper app integration class for this service

        Args:
            remediation_id: The remediation id

        Returns: Subclass of RemediationBase corresponding to the remediation id

        Raises:
            RemediationDoesntExist: Raised if remediation doesn't exist
            for the specified remediation id
        """
        try:
            return cls._remediations[remediation_id]
        except KeyError:
            raise RemediationDoesNotExist('Remediation with id {} does not exist'.format(remediation_id))

    @classmethod
    def get_all_remediations(cls) -> Dict[str, Dict[str, str]]:
        """
        Returns the list of available remediations, along with the parameters
        these remediations use.

        Returns: A map of remediationId -> list of parameters.
        """
        result = {}
        for remediation in cls._remediations.values():
            result[remediation.remediation_id()] = remediation.parameters()
        return result
