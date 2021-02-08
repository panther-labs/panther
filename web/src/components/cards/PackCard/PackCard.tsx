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
import GenericItemCard from 'Components/GenericItemCard';
import { Box, Card, Flex, Link, Text, useSnackbar } from 'pouncejs';
import { Link as RRLink } from 'react-router-dom';
import urls from 'Source/urls';
import UpdateVersion, { UpdateVersionFormValues } from 'Components/cards/PackCard/UpdateVersion';
import { useUpdatePack } from 'Source/graphql/queries';
import { EventEnum, SrcEnum, trackError, TrackErrorEnum, trackEvent } from 'Helpers/analytics';
import { extractErrorMessage } from 'Helpers/utils';
import BulletedLoading from 'Components/BulletedLoading';
import UpdateStatus, { UpdateStatusFormValues } from 'Components/cards/PackCard/UpdateStatus';
import { PackDetails } from 'Source/graphql/fragments/PackDetails.generated';

interface PackCardProps {
  pack: PackDetails;
}

const PackCard: React.FC<PackCardProps> = ({ pack }) => {
  const { pushSnackbar } = useSnackbar();

  const [updatePack, { loading }] = useUpdatePack({
    // This hook ensures we also update the AlertDetails item in the cache
    update: (cache, { data }) => {
      const dataId = cache.identify({
        __typename: 'PackDetails',
        id: data.updatePack.id,
      });
      cache.modify(dataId, {
        enabled: () => data.updatePack.enabled,
        packVersion: () => data.updatePack.packVersion,
      });
      // TODO: when apollo client is updated to 3.0.0-rc.12+, use this code
      // cache.modify({
      //   id: cache.identify({
      //     __typename: 'PackDetails',
      //     id: data.updatePack.alertId,
      //   }),
      //   fields: {
      //     packVersion: () => data.updatePack.packVersion,
      //     enabled: () => data.updatePack.enabled,
      //   },
      // });
    },
    onCompleted: data => {
      trackEvent({
        event: EventEnum.UpdatedPack,
        src: SrcEnum.Packs,
      });
      pushSnackbar({
        variant: 'success',
        title: `Updated Pack [${data.updatePack.id}] successfully`,
      });
    },
    onError: error => {
      trackError({
        event: TrackErrorEnum.FailedToUpdatePack,
        src: SrcEnum.Packs,
      });
      pushSnackbar({
        variant: 'error',
        title: `Failed to update Pack`,
        description: extractErrorMessage(error),
      });
    },
  });

  const onPatch = (values: UpdateVersionFormValues) => {
    return updatePack({
      variables: {
        input: {
          id: pack.id,
          packVersion: values.packVersion,
        },
      },
    });
  };

  const onStatusUpdate = (values: UpdateStatusFormValues) => {
    return updatePack({
      variables: {
        input: {
          id: pack.id,
          enabled: values.enabled,
        },
      },
    });
  };
  return (
    // Replaced GenericItemCard with simple card in order to exclude overflow property
    <Card as="section" variant="dark" position="relative">
      {loading && (
        <Flex
          position="absolute"
          direction="column"
          spacing={2}
          backgroundColor="navyblue-700"
          height="100%"
          zIndex={2}
          alignItems="center"
          opacity={0.9}
          justify="center"
          width={1}
        >
          <Text textAlign="center" opacity={1}>
            The pack is updating, please wait.
          </Text>
          <BulletedLoading />
        </Flex>
      )}
      <Flex position="relative" height="100%" p={4}>
        <GenericItemCard.Body>
          <GenericItemCard.Header>
            <GenericItemCard.Heading>
              <Link as={RRLink} aria-label="Link to Pack" to={urls.packs.details(pack.id)}>
                {pack.displayName || pack.id}
              </Link>
            </GenericItemCard.Heading>
            <Flex spacing={2} fontSize="small" alignItems="center">
              {pack.updateAvailable && (
                <Box
                  as="span"
                  backgroundColor="red-500"
                  borderRadius="small"
                  px={2}
                  py={1}
                  fontWeight="bold"
                >
                  UPDATE AVAILABLE
                </Box>
              )}
              <Text as="span">Version</Text>
              <Text as="span" color="gray-400">
                {pack.packVersion.name}
              </Text>
            </Flex>
          </GenericItemCard.Header>
          <Flex spacing={2}>
            <Box
              as="span"
              backgroundColor="navyblue-700"
              borderRadius="small"
              p={1}
              fontSize="small"
              color="cyan-500"
              mr={1}
            >
              {pack.detectionTypes.RULE} Rules
            </Box>
            <Box
              backgroundColor="navyblue-700"
              borderRadius="small"
              p={1}
              fontSize="small"
              color="indigo-300"
            >
              {pack.detectionTypes.POLICY} Policies
            </Box>
            <Box
              backgroundColor="navyblue-700"
              borderRadius="small"
              px={1}
              py={1}
              fontSize="small"
              color="green-200"
            >
              {pack.detectionTypes.GLOBAL} Helpers
            </Box>
          </Flex>
          <GenericItemCard.ValuesGroup>
            <Flex width={1} mt={3}>
              <Box width={0.6}>
                <GenericItemCard.Value label="Pack Description" value={pack.description} />
              </Box>
              <Box width="250px">
                <UpdateVersion pack={pack} onPatch={onPatch} />
              </Box>
              <Flex ml="auto" mr={0} align="flex-end">
                <UpdateStatus pack={pack} onUpdate={onStatusUpdate} />
              </Flex>
            </Flex>
          </GenericItemCard.ValuesGroup>
        </GenericItemCard.Body>
      </Flex>
    </Card>
  );
};

export default React.memo(PackCard);
