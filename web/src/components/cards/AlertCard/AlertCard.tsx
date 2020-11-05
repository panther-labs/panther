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
import { Checkbox, Flex, Icon, Link, Text } from 'pouncejs';
import { Link as RRLink } from 'react-router-dom';
import SeverityBadge from 'Components/badges/SeverityBadge';
import React from 'react';
import urls from 'Source/urls';
import LinkButton from 'Components/buttons/LinkButton';
import RelatedDestinations from 'Components/RelatedDestinations';
import BulletedLogTypeList from 'Components/BulletedLogTypeList';
import { AlertSummaryFull } from 'Source/graphql/fragments/AlertSummaryFull.generated';
import { formatDatetime } from 'Helpers/utils';
import useAlertDestinations from 'Hooks/useAlertDestinations';
import useAlertDestinationsDeliverySuccess from 'Hooks/useAlertDestinationsDeliverySuccess';
import UpdateAlertDropdown from '../../dropdowns/UpdateAlertDropdown';

interface AlertCardSimpleProps {
  alert: AlertSummaryFull;
  hideRuleButton?: boolean;
  selectionEnabled?: false | null;
  selected?: null;
  onSelect?: null;
  onDeselect?: null;
}

interface AlertCardWithSelectionProps {
  alert: AlertSummaryFull;
  hideRuleButton?: boolean;
  selectionEnabled: true;
  selected: string[];
  onSelect: (string) => void;
  onDeselect: (string) => void;
}

type AlertCardProps = AlertCardSimpleProps | AlertCardWithSelectionProps;

const AlertCard: React.FC<AlertCardProps> = ({
  alert,
  hideRuleButton = false,
  selectionEnabled = false,
  selected,
  onSelect,
  onDeselect,
}) => {
  const { alertDestinations, loading: loadingDestinations } = useAlertDestinations({ alert });
  const { allDestinationDeliveredSuccessfully, loading } = useAlertDestinationsDeliverySuccess({
    alert,
  });

  const isAlertSelected = selected && selected.find(a => a === alert.alertId);
  return (
    <GenericItemCard>
      <Flex align="start" pr={2}>
        {selectionEnabled && (
          <Checkbox
            checked={!!isAlertSelected}
            onClick={() => (isAlertSelected ? onDeselect(alert.alertId) : onSelect(alert.alertId))}
            aria-label="select alert"
          />
        )}
      </Flex>
      <GenericItemCard.Body>
        <GenericItemCard.Heading>
          <Link
            as={RRLink}
            aria-label="Link to Alert"
            to={urls.logAnalysis.alerts.details(alert.alertId)}
          >
            {alert.title}
          </Link>
        </GenericItemCard.Heading>
        <GenericItemCard.ValuesGroup>
          {!hideRuleButton && (
            <GenericItemCard.Value
              value={
                <LinkButton
                  aria-label="Link to Rule"
                  to={urls.logAnalysis.rules.details(alert.ruleId)}
                  variantColor="navyblue"
                  size="medium"
                >
                  View Rule
                </LinkButton>
              }
            />
          )}

          <GenericItemCard.Value
            label="Destinations"
            value={
              <RelatedDestinations destinations={alertDestinations} loading={loadingDestinations} />
            }
          />
          <GenericItemCard.Value
            label="Log Types"
            value={<BulletedLogTypeList logTypes={alert.logTypes} limit={2} />}
          />
          <GenericItemCard.Value
            label="Events"
            value={alert?.eventsMatched ? alert?.eventsMatched.toLocaleString() : '0'}
          />
          <GenericItemCard.Value label="Time Created" value={formatDatetime(alert.creationTime)} />
          <Flex ml="auto" mr={0} align="flex-end" spacing={2}>
            <SeverityBadge severity={alert.severity} />
            <UpdateAlertDropdown alert={alert} />
          </Flex>
        </GenericItemCard.ValuesGroup>
        {!loading && !allDestinationDeliveredSuccessfully && (
          <Flex
            as="section"
            align="center"
            spacing={2}
            mt={2}
            aria-label="Destination delivery failure"
          >
            <Icon type="alert-circle-filled" size="medium" color="red-300" />
            <Text fontSize="small" fontStyle="italic" color="red-300">
              There was an issue with the delivery of this alert to a selected destination. See
              specific Alert for details.
            </Text>
          </Flex>
        )}
      </GenericItemCard.Body>
    </GenericItemCard>
  );
};

export default React.memo(AlertCard);
