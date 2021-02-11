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

import React from 'react';
import { Box, Button, Flex, Card, Heading } from 'pouncejs';
import { Rule } from 'Generated/schema';
import urls from 'Source/urls';
import useModal from 'Hooks/useModal';
import { MODALS } from 'Components/utils/Modal';
import SeverityBadge from 'Components/badges/SeverityBadge';
import StatusBadge from 'Components/badges/StatusBadge';
import LinkButton from 'Components/buttons/LinkButton';
import Breadcrumbs from 'Components/Breadcrumbs';
import BulletedValue from 'Components/BulletedValue';
import RelatedDestinations from 'Components/RelatedDestinations/RelatedDestinations';
import useDetectionDestinations from 'Hooks/useDetectionDestinations';

interface ResourceDetailsInfoProps {
  rule?: Rule;
}

const RuleDetailsBanner: React.FC<ResourceDetailsInfoProps> = ({ rule }) => {
  const { showModal } = useModal();
  const {
    detectionDestinations,
    loading: loadingDetectionDestinations,
  } = useDetectionDestinations({ detection: rule });

  return (
    <React.Fragment>
      <Breadcrumbs.Actions>
        <Flex spacing={4} justify="flex-end">
          <LinkButton
            icon="pencil"
            aria-label="Edit Rule"
            to={urls.logAnalysis.rules.edit(rule.id)}
          >
            Edit Rule
          </LinkButton>
          <Button
            icon="trash"
            variantColor="red"
            aria-label="Delete Rule"
            onClick={() =>
              showModal({
                modal: MODALS.DELETE_DETECTIONS,
                props: { detections: [rule] },
              })
            }
          >
            Delete Rule
          </Button>
        </Flex>
      </Breadcrumbs.Actions>
      <Card as="article" p={6} borderLeft="4px solid" borderColor="cyan-500">
        <Flex as="header" align="center">
          <Heading
            fontWeight="bold"
            wordBreak="break-word"
            aria-describedby="rule-description"
            flexShrink={1}
            display="flex"
            alignItems="center"
            mr={100}
          >
            {rule.displayName || rule.id}
          </Heading>
          <Flex spacing={2} as="ul" flexShrink={0} ml="auto">
            <Box as="li">
              <StatusBadge status="ENABLED" disabled={!rule.enabled} />
            </Box>
            <Box as="li">
              <SeverityBadge severity={rule.severity} />
            </Box>
          </Flex>
        </Flex>
        <Flex as="dl" fontSize="small-medium" pt={5} spacing={8} wrap="wrap">
          <Flex>
            <Box color="navyblue-100" as="dt" pr={2}>
              Detection Type
            </Box>
            <Box as="dd" fontWeight="bold" color="cyan-400">
              Rule
            </Box>
          </Flex>
          <Flex>
            <Box color="navyblue-100" as="dt" pr={2}>
              Rule ID
            </Box>
            <Box as="dd" fontWeight="bold">
              {rule.id}
            </Box>
          </Flex>
          <Flex>
            <Box color="navyblue-100" as="dt" pr={2}>
              Log Types
            </Box>
            <Flex as="dd" align="center" spacing={6}>
              {rule.logTypes.map(logType => (
                <BulletedValue key={logType} value={logType} />
              ))}
            </Flex>
          </Flex>
          <Flex>
            <Box color="navyblue-100" as="dt" pr={2}>
              Destinations
            </Box>
            <Box as="dd">
              <RelatedDestinations
                destinations={detectionDestinations}
                loading={loadingDetectionDestinations}
                limit={5}
              />
            </Box>
          </Flex>
        </Flex>
      </Card>
    </React.Fragment>
  );
};

export default React.memo(RuleDetailsBanner);
