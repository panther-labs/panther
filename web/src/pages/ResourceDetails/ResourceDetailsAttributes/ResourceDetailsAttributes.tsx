/*
<IconButton
          variant="ghost"
          active={open}
          variantColor="navyblue"
          icon={open ? 'caret-up' : 'caret-down'}
          onClick={() => setOpen(!open)}
          aria-label="Toggle Editor visibility"
        />
 */
import React from 'react';
import { Text, Box, Card, Flex, IconButton } from 'pouncejs';
import JsonViewer from 'Components/JsonViewer';
import Panel from 'Components/Panel';
import { ComplianceIntegration, ResourceDetails } from 'Generated/schema';

interface ResourceDetailsAttributesProps {
  resource?: ResourceDetails & Pick<ComplianceIntegration, 'integrationLabel'>;
}

const ResourceDetailsAttributes: React.FC<ResourceDetailsAttributesProps> = ({ resource }) => {
  const [open, setOpen] = React.useState(true);
  return (
    <Panel title="Attributes">
      <Card p={4} variant="dark">
        <Flex align={open ? 'flex-start' : 'center'} spacing={open ? 7 : 2}>
          <IconButton
            variant="ghost"
            size="small"
            active={open}
            variantColor="navyblue"
            icon={open ? 'caret-up' : 'caret-down'}
            onClick={() => setOpen(!open)}
            aria-label="Toggle attributes visibility"
          />

          {open ? (
            <JsonViewer data={JSON.parse(resource.attributes)} />
          ) : (
            <Text as="span" size="small" color="gray-300">
              Click to expand
            </Text>
          )}
        </Flex>
      </Card>
    </Panel>
  );
};

export default ResourceDetailsAttributes;
