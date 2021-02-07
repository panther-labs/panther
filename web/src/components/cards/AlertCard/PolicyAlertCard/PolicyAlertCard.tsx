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
import { AlertSummaryPolicyInfo } from 'Generated/schema';
import { Link as RRLink } from 'react-router-dom';
import SeverityBadge from 'Components/badges/SeverityBadge';
import React from 'react';
import urls from 'Source/urls';
import RelatedDestinations from 'Components/RelatedDestinations';
import BulletedValueList from 'Components/BulletedValueList';
import { AlertSummaryFull } from 'Source/graphql/fragments/AlertSummaryFull.generated';
import { formatDatetime } from 'Helpers/utils';
import { useListComplianceSourceNames } from 'Source/graphql/queries';
import useAlertDestinations from 'Hooks/useAlertDestinations';
import useAlertDestinationsDeliverySuccess from 'Hooks/useAlertDestinationsDeliverySuccess';
import { SelectCheckbox } from 'Components/utils/SelectContext';
import UpdateAlertDropdown from 'Components/dropdowns/UpdateAlertDropdown';

export interface PolicyAlertCardProps {
  alert: AlertSummaryFull;
  hidePolicyButton?: boolean;
  selectionEnabled?: boolean;
}

const PolicyAlertCard: React.FC<PolicyAlertCardProps> = ({
  alert,
  hidePolicyButton = false,
  selectionEnabled = false,
}) => {
  const { data: complianceSourceData } = useListComplianceSourceNames({ errorPolicy: 'ignore' });
  const { alertDestinations, loading: loadingDestinations } = useAlertDestinations({ alert });
  const { allDestinationDeliveredSuccessfully, loading } = useAlertDestinationsDeliverySuccess({
    alert,
  });

  const detectionData = alert.detection as AlertSummaryPolicyInfo;
  const source = complianceSourceData?.listComplianceIntegrations?.find(
    s => s.integrationId === detectionData.policySourceId
  );

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
        <Text fontSize="small" as="span" color="cyan-400">
          Policy Fail
        </Text>
        <GenericItemCard.ValuesGroup>
          {!hidePolicyButton && (
            <GenericItemCard.Value
              label="Policy"
              value={
                <Flex spacing={2}>
                  <Text display="inline-flex" alignItems="center" as="span">
                    {detectionData.policyId}
                  </Text>
                  <GenericItemCard.Link
                    aria-label={`Link to policy ${detectionData.policyId}`}
                    to={urls.compliance.policies.details(detectionData.policyId)}
                  />
                </Flex>
              }
            />
          )}
          <GenericItemCard.Value label="Source" value={source ? source.integrationLabel : null} />
          <GenericItemCard.Value
            label="Destinations"
            value={
              <RelatedDestinations destinations={alertDestinations} loading={loadingDestinations} />
            }
          />
          <GenericItemCard.Value
            label="Resource Types"
            value={<BulletedValueList values={detectionData.resourceTypes} limit={2} />}
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

export default React.memo(PolicyAlertCard);
