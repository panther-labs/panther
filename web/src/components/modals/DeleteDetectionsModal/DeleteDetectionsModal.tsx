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

/**
 * Copyright (C) 2020 Panther Labs Inc
 *
 * Panther Enterprise is licensed under the terms of a commercial license available from
 * Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
 * All use, distribution, and/or modification of this software, whether commercial or non-commercial,
 * falls under the Panther Commercial License to the extent it is permitted.
 */

import React from 'react';
import { Reference } from '@apollo/client';
import { DetectionTypeEnum } from 'Generated/schema';
import { RuleSummary } from 'Source/graphql/fragments/RuleSummary.generated';
import { PolicySummary } from 'Source/graphql/fragments/PolicySummary.generated';
import OptimisticConfirmModal from 'Components/modals/OptimisticConfirmModal';
import { ModalProps, useSnackbar } from 'pouncejs';
import useRouter from 'Hooks/useRouter';
import urls from 'Source/urls';
import differenceBy from 'lodash/differenceBy';
import { extractErrorMessage, toPlural } from 'Helpers/utils';
import { EventEnum, SrcEnum, trackError, TrackErrorEnum, trackEvent } from 'Helpers/analytics';
import { useDeleteDetections } from './graphql/deleteDetections.generated';

export interface DeleteDetectionsModalProps extends ModalProps {
  detections: (RuleSummary | PolicySummary)[];
  onSuccess?: () => void;
}

const DeleteDetectionsModal: React.FC<DeleteDetectionsModalProps> = ({
  detections,
  onSuccess = () => {},
  ...rest
}) => {
  const { location, history } = useRouter<{ id?: string }>();
  const { pushSnackbar } = useSnackbar();

  const isMultiDelete = detections.length > 1;
  const modalTitle = isMultiDelete ? `Delete ${detections.length} Detections` : `Delete Detection`;
  const modalDescription = `Are you sure you want to delete ${
    isMultiDelete
      ? `${detections.length} detections`
      : detections[0].displayName || detections[0].id
  }?`;

  const [confirmDeletion] = useDeleteDetections({
    variables: {
      input: {
        detections: detections.map(detection => ({ id: detection.id })),
      },
    },
    optimisticResponse: {
      deleteDetections: true,
    },
    update: async cache => {
      cache.modify('ROOT_QUERY', {
        detections: (data, helpers) => {
          const detectionRefs = detections.map(detection =>
            helpers.toReference({
              __typename: detection.analysisType === DetectionTypeEnum.Policy ? 'Policy' : 'Rule',
              id: detection.id,
            })
          );

          return {
            ...data,
            detections: differenceBy(data.detections, detectionRefs, d => (d as Reference).__ref),
          };
        },
        rule: (data, helpers) => {
          const ruleRefs = detections
            .filter(detection => detection.analysisType !== DetectionTypeEnum.Policy)
            .map(detection =>
              helpers.toReference({
                __typename: 'Rule',
                id: detection.id,
              })
            );

          const deletedRuleExistsInCache = ruleRefs.find(policy => policy.__ref === data.__ref);
          if (deletedRuleExistsInCache) {
            return helpers.DELETE;
          }
          return data;
        },
        policy: (data, helpers) => {
          const policyRefs = detections
            .filter(detection => detection.analysisType === DetectionTypeEnum.Policy)
            .map(detection =>
              helpers.toReference({
                __typename: 'Policy',
                id: detection.id,
              })
            );

          const deletedPolicyExistsInCache = policyRefs.find(policy => policy.__ref === data.__ref);
          if (deletedPolicyExistsInCache) {
            return helpers.DELETE;
          }
          return data;
        },
      });
      cache.gc();
    },
    onCompleted: () => {
      trackEvent({
        event: EventEnum.DeletedDetection,
        src: SrcEnum.Detections,
      });

      pushSnackbar({
        variant: 'success',
        title: `Successfully deleted ${toPlural(
          'detection',
          `${detections.length} detections`,
          detections.length
        )}`,
      });
    },
    onError: error => {
      trackError({
        event: TrackErrorEnum.FailedToDeleteDetection,
        src: SrcEnum.Detections,
      });

      pushSnackbar({
        variant: 'error',
        title: `Failed to delete ${toPlural(
          'detection',
          `${detections.length} detectioons`,
          detections.length
        )}`,
        description: extractErrorMessage(error),
      });
    },
  });

  const handleConfirm = () => {
    if (!isMultiDelete && location.pathname.includes(detections[0].id)) {
      // if we were on the particular detection's details page or edit page --> redirect on delete
      history.push(urls.detections.list());
    }

    confirmDeletion();
    onSuccess();
  };

  return (
    <OptimisticConfirmModal
      title={modalTitle}
      subtitle={modalDescription}
      onConfirm={handleConfirm}
      {...rest}
    />
  );
};

export default DeleteDetectionsModal;
