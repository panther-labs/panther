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
import { Box, Flex, Card, Heading, Switch, useSnackbar, Text } from 'pouncejs';
import UpdateVersion, { UpdateVersionFormValues } from 'Components/cards/PackCard/UpdateVersion';
import { EventEnum, SrcEnum, trackError, TrackErrorEnum, trackEvent } from 'Helpers/analytics';
import { extractErrorMessage } from 'Helpers/utils';
import BulletedLoading from 'Components/BulletedLoading';
import { AnalysisPackSummary } from 'Source/graphql/fragments/AnalysisPackSummary.generated';
import { useUpdateAnalysisPack } from 'Source/graphql/queries';

interface AnalysisPackDetailsBannerProps {
  pack?: AnalysisPackSummary;
}

const AnalysisPackDetailsBanner: React.FC<AnalysisPackDetailsBannerProps> = ({ pack }) => {
  const { pushSnackbar } = useSnackbar();

  const [updatePack, { loading }] = useUpdateAnalysisPack({
    onCompleted: data => {
      trackEvent({
        event: EventEnum.UpdatedPack,
        src: SrcEnum.Packs,
      });
      pushSnackbar({
        variant: 'success',
        title: `Updated Pack [${data.updateAnalysisPack.id}] successfully`,
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

  const onPatch = React.useCallback(
    (values: UpdateVersionFormValues) => {
      return updatePack({
        variables: {
          input: {
            id: pack.id,
            versionId: values.packVersion.id,
          },
        },
      });
    },
    [pack]
  );

  const onStatusUpdate = React.useCallback(() => {
    return updatePack({
      variables: {
        input: {
          id: pack.id,
          enabled: !pack.enabled,
        },
      },
    });
  }, [pack]);

  return (
    <Card as="article" position="relative">
      {loading && (
        <Flex
          position="absolute"
          direction="column"
          spacing={2}
          backgroundColor="navyblue-700"
          height="100%"
          zIndex={2}
          align="center"
          opacity={0.9}
          justify="center"
          width={1}
        >
          <Text textAlign="center" opacity={1} fontWeight="bold">
            {pack.displayName || pack.id}
          </Text>
          <Text textAlign="center" opacity={1}>
            is being updated, please wait.
          </Text>
          <BulletedLoading />
        </Flex>
      )}
      <Flex p={6}>
        <Box>
          <Flex as="header" align="center">
            <Heading
              fontWeight="bold"
              wordBreak="break-word"
              aria-describedby="rule-description"
              flexShrink={1}
              display="flex"
              alignItems="center"
              mr={4}
            >
              {pack.displayName || pack.id}
            </Heading>
            {pack.updateAvailable && (
              <Box
                as="span"
                backgroundColor={pack.enabled ? 'red-500' : 'gray-500'}
                borderRadius="small"
                px={2}
                py={1}
                fontSize="small"
                fontWeight="bold"
              >
                UPDATE AVAILABLE
              </Box>
            )}
          </Flex>
          <Flex as="dl" fontSize="medium" pt={2} spacing={8} wrap="wrap">
            {pack.description}
          </Flex>
        </Box>
        <Flex align="center" spacing={8} flexShrink={0} ml="auto">
          <Flex ml="auto" mr={0} align="flex-end">
            <Switch onClick={onStatusUpdate} label="Enabled" checked={pack.enabled} />
          </Flex>
          <Box width="250px">
            <UpdateVersion pack={pack} onPatch={onPatch} />
          </Box>
        </Flex>
      </Flex>
    </Card>
  );
};

export default React.memo(AnalysisPackDetailsBanner);
