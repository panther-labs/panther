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
import { Flex, Icon, Link, Text, Box } from 'pouncejs';
import { AlertSummaryRuleInfo, AlertTypesEnum } from 'Generated/schema';
import { Link as RRLink } from 'react-router-dom';
import SeverityBadge from 'Components/badges/SeverityBadge';
import React from 'react';
import urls from 'Source/urls';
import RelatedDestinations from 'Components/RelatedDestinations';
import BulletedValueList from 'Components/BulletedValueList';
import { AlertSummaryFull } from 'Source/graphql/fragments/AlertSummaryFull.generated';
import { formatDatetime } from 'Helpers/utils';
import useAlertDestinations from 'Hooks/useAlertDestinations';
import useAlertDestinationsDeliverySuccess from 'Hooks/useAlertDestinationsDeliverySuccess';
import { SelectCheckbox } from 'Components/utils/SelectContext';
import UpdateAlertDropdown from 'Components/dropdowns/UpdateAlertDropdown';

export interface RuleAlertCardProps {
  alert: AlertSummaryFull;
  hideRuleButton?: boolean;
  selectionEnabled?: boolean;
}

const RuleAlertCard: React.FC<RuleAlertCardProps> = ({
  alert,
  hideRuleButton = false,
  selectionEnabled = false,
}) => {
  const { alertDestinations, loading: loadingDestinations } = useAlertDestinations({ alert });
  const { allDestinationDeliveredSuccessfully, loading } = useAlertDestinationsDeliverySuccess({
    alert,
  });

  const detectionData = alert.detection as AlertSummaryRuleInfo;
  return (
    <GenericItemCard>
      <Flex align="start" pr={2}>
        {selectionEnabled && (
          <Box transform="translate3d(0,-8px,0)">
            <SelectCheckbox selectionItem={alert.alertId} />
          </Box>
        )}
      </Flex>
      <GenericItemCard.Body>
        <GenericItemCard.Header>
          <GenericItemCard.Heading>
            <Link
              as={RRLink}
              aria-label="Link to Alert"
              to={urls.logAnalysis.alerts.details(alert.alertId)}
            >
              {alert.title}
            </Link>
          </GenericItemCard.Heading>
          <GenericItemCard.Date
            aria-label={`Creation time for ${alert.alertId}`}
            date={formatDatetime(alert.creationTime)}
          />
        </GenericItemCard.Header>
        <Text
          fontSize="small"
          as="span"
          color={alert.type === AlertTypesEnum.Rule ? 'red-300' : 'teal-500'}
        >
          {alert.type === AlertTypesEnum.Rule ? 'Rule Match' : 'Rule Error'}
        </Text>
        <GenericItemCard.ValuesGroup>
          {!hideRuleButton && (
            <GenericItemCard.Value
              label="Rule"
              value={
                <Flex spacing={2}>
                  <Text display="inline-flex" alignItems="center" as="span">
                    {detectionData.ruleId}
                  </Text>
                  <GenericItemCard.Link
                    aria-label={`Link to rule ${detectionData.ruleId}`}
                    to={urls.logAnalysis.rules.details(detectionData.ruleId)}
                  />
                </Flex>
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
            value={<BulletedValueList values={detectionData.logTypes} limit={2} />}
          />
          <GenericItemCard.Value
            label="Events"
            value={
              detectionData?.eventsMatched ? detectionData?.eventsMatched.toLocaleString() : '0'
            }
          />
          <Flex ml="auto" mr={0} align="flex-end" spacing={2}>
            <SeverityBadge severity={alert.severity} />
            <UpdateAlertDropdown alert={alert} />
          </Flex>
        </GenericItemCard.ValuesGroup>
        {!loading && !allDestinationDeliveredSuccessfully && (
          <Flex
            as="section"
            align="center"
            spacing={1}
            mt={2}
            aria-label="Destination delivery failure"
            fontStyle="italic"
            color="red-100"
            fontSize="small"
          >
            <Icon type="alert-circle-filled" size="medium" />
            <Text>
              There was an issue with the delivery of this alert to a selected destination.
            </Text>
            <RRLink to={urls.logAnalysis.alerts.details(alert.alertId)}>
              <Text textDecoration="underline">See details</Text>
            </RRLink>
          </Flex>
        )}
      </GenericItemCard.Body>
    </GenericItemCard>
  );
};

export default React.memo(RuleAlertCard);
