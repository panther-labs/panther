import React from 'react';
import { Box, SimpleGrid } from 'pouncejs';
import ErrorBoundary from 'Components/ErrorBoundary';
import useUrlParams from 'Hooks/useUrlParams';
import withSEO from 'Hoc/withSEO';
import CreateRule from './CreateRule';
import CreatePolicy from './CreatePolicy';
import DetectionSelectionCard from './DetectionSelectionCard';

export interface CreateDetectionUrlParams {
  type?: 'rule' | 'policy' | 'scheduledRule';
}

const CreateDetection: React.FC = () => {
  const {
    urlParams: { type },
    setUrlParams,
  } = useUrlParams<CreateDetectionUrlParams>();

  React.useLayoutEffect(() => {
    if (!type) {
      setUrlParams({ type: 'rule' });
    }
  }, [type, useUrlParams]);

  return (
    <React.Fragment>
      <SimpleGrid spacing={4} columns={3}>
        <DetectionSelectionCard
          type="rule"
          title="Rule"
          description="Python3 functions used to identify suspicious activity and generate helpful signals for your team."
          icon="log-analysis"
          iconColor="cyan-500"
        />
        <DetectionSelectionCard
          type="policy"
          title="Policy"
          description="Python3 functions used to identify misconfigured infrastructure and generate alerts for your team."
          icon="cloud-security"
          iconColor="violet-300"
        />
        <DetectionSelectionCard
          availableInEnterprise
          title="Scheduled Rule"
          description="Python3 functions used to identify suspicious activity that run on a schedule"
          icon="schedule"
          iconColor="pink-400"
        />
      </SimpleGrid>
      <Box py={6}>
        <ErrorBoundary>
          {type === 'rule' && <CreateRule />}
          {type === 'policy' && <CreatePolicy />}
        </ErrorBoundary>
      </Box>
    </React.Fragment>
  );
};

export default withSEO({ title: 'New Detection' })(CreateDetection);
