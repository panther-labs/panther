/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import GenericItemCard from 'Components/GenericItemCard';
import { Flex, Link, Button, Text } from 'pouncejs';
import { Link as RRLink } from 'react-router-dom';
import SeverityBadge from 'Components/badges/SeverityBadge';
import React from 'react';
import urls from 'Source/urls';
import { AlertSummaryFull } from 'Source/graphql/fragments/AlertSummaryFull.generated';
import { formatDatetime } from 'Helpers/utils';
import UpdateAlertDropdown from '../../dropdowns/UpdateAlertDropdown';

interface AlertCardProps {
  alert: AlertSummaryFull;
}

const AlertCard: React.FC<AlertCardProps> = ({ alert }) => {
  return (
    <GenericItemCard>
      <GenericItemCard.Body>
        <Link
          external
          as={RRLink}
          to={urls.logAnalysis.alerts.details(alert.alertId)}
          cursor="pointer"
        >
          <GenericItemCard.Heading>{alert.title}</GenericItemCard.Heading>
        </Link>
        <GenericItemCard.ValuesGroup>
          <Link external as={RRLink} mt={4} to={urls.logAnalysis.rules.details(alert.ruleId)}>
            <Button variantColor="navyblue" as="div">
              <Text fontSize="small">View Rule</Text>
            </Button>
          </Link>
          <GenericItemCard.Value label="Events" value={alert.eventsMatched} />
          <GenericItemCard.Value label="Time Created" value={formatDatetime(alert.creationTime)} />
          <Flex ml="auto" mr={0} align="flex-end" alignItems="center" spacing={2}>
            <SeverityBadge severity={alert.severity} />
            <UpdateAlertDropdown alert={alert} />
          </Flex>
        </GenericItemCard.ValuesGroup>
      </GenericItemCard.Body>
    </GenericItemCard>
  );
};

export default React.memo(AlertCard);
