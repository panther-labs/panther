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
import { Box, Flex, Card, Icon, Text, Heading, SimpleGrid, Link, FadeIn, Img } from 'pouncejs';
import logo from 'Source/assets/panther-minimal-logo.svg';
import urls from 'Source/urls';
import { PANTHER_DOCS_LINK } from 'Source/constants';
import { pantherConfig } from 'Source/config';
import withSEO from 'Hoc/withSEO';
import { AlertStatusesEnum } from 'Generated/schema';
import useTrackPageView from 'Hooks/useTrackPageView';
import { PageViewEnum } from 'Helpers/analytics';
import LinkButton from 'Components/buttons/LinkButton';

const LandingPage: React.FC = () => {
  useTrackPageView(PageViewEnum.Home);

  return (
    <FadeIn delay={100}>
      <Box as="article" textAlign="center">
        <Box my={60}>
          <Flex width={1} justify="center">
            <Img src={logo} alt="Panther logo" nativeWidth="60" nativeHeight="60" />
          </Flex>

          <Heading size="2x-large" mb={2} mt={5}>
            Welcome!
          </Heading>
          <Heading as="h2" size="small">
            Let{"'"}s get you started with Panther
          </Heading>
        </Box>
        <Card mb={6} p={4} as="section">
          <SimpleGrid columns={3} py={5}>
            <Flex direction="column" align="center" justify="center">
              <Icon type="user" mb={4} size="large" />
              <Heading size="x-small" as="h4" mb={4}>
                Invite your team
              </Heading>
              <Text fontSize="medium" color="gray-300" mb={6} maxWidth={275}>
                Create users and get your team onboarded to Panther
              </Text>
              <Box width={225}>
                <LinkButton to={urls.settings.users()} fullWidth variantColor="teal">
                  Manage Users
                </LinkButton>
              </Box>
            </Flex>
            <Flex direction="column" justify="center" align="center">
              <Icon type="infra-source" mb={4} size="large" />
              <Heading size="x-small" as="h4" mb={4}>
                Setup Infrastructure Monitoring
              </Heading>
              <Text fontSize="medium" color="gray-300" mb={6} maxWidth={275}>
                Connect AWS accounts, scan resources and detect misconfigurations
              </Text>
              <Box width={225}>
                <LinkButton
                  to={urls.integrations.cloudAccounts.create()}
                  fullWidth
                  variantColor="teal"
                >
                  Onboard an AWS account
                </LinkButton>
              </Box>
            </Flex>
            <Flex direction="column" justify="center" align="center">
              <Icon type="log-source" mb={4} size="large" />
              <Heading size="x-small" as="h4" mb={4}>
                Setup your Log Sources
              </Heading>
              <Text fontSize="medium" color="gray-300" mb={6} maxWidth={275}>
                Connect your log buckets and analyze data with rules
              </Text>
              <Box width={225}>
                <LinkButton
                  to={urls.integrations.logSources.create()}
                  fullWidth
                  variantColor="teal"
                >
                  Connect S3 Buckets
                </LinkButton>
              </Box>
            </Flex>
          </SimpleGrid>
        </Card>

        <Card mb={6} p={4} as="section">
          <SimpleGrid columns={3} py={5}>
            <Flex direction="column" align="center" justify="center">
              <Icon type="output" mb={4} size="large" />
              <Heading size="x-small" as="h4" mb={4}>
                Setup an Alert Destination
              </Heading>
              <Text fontSize="medium" color="gray-300" mb={6} maxWidth={275}>
                Add destinations so Panther can notify you of policy and rule findings
              </Text>
              <Box width={225}>
                <LinkButton to={urls.integrations.destinations.list()} fullWidth variantColor="red">
                  Setup Destinations
                </LinkButton>
              </Box>
            </Flex>

            <Flex direction="column" align="center" justify="center">
              <Icon type="policy" mb={4} size="large" />
              <Heading size="x-small" as="h4" mb={4}>
                Write Infrastructure Policies
              </Heading>
              <Text fontSize="medium" color="gray-300" mb={6} maxWidth={275}>
                Create Cloud Security policies to evaluate your AWS infrastructure
              </Text>
              <Box width={225}>
                <LinkButton to={urls.compliance.policies.create()} fullWidth variantColor="red">
                  Create a Policy
                </LinkButton>
              </Box>
            </Flex>
            <Flex direction="column" align="center" justify="center">
              <Icon type="rule" mb={4} size="large" />
              <Heading size="x-small" as="h4" mb={4}>
                Write Log Detection Rules
              </Heading>
              <Text fontSize="medium" color="gray-300" mb={6} maxWidth={275}>
                Create rules to evaluate your logs and trigger alerts on suspicious activity
              </Text>
              <Box width={225}>
                <LinkButton to={urls.logAnalysis.rules.create()} fullWidth variantColor="red">
                  Create a Rule
                </LinkButton>
              </Box>
            </Flex>
          </SimpleGrid>
        </Card>
        <Card as="section" p={4}>
          <SimpleGrid columns={3} py={5}>
            <Flex direction="column" align="center" justify="center">
              <Icon type="alert" mb={4} size="large" />
              <Heading size="x-small" as="h4" mb={4}>
                Triage Alerts
              </Heading>
              <Text fontSize="medium" color="gray-300" mb={6} maxWidth={275}>
                View all alerts generated by rules that ran against your logs
              </Text>
              <Box width={225}>
                <LinkButton
                  to={`${urls.logAnalysis.alerts.list()}?status[]=${
                    AlertStatusesEnum.Open
                  }&status[]=${AlertStatusesEnum.Triaged}`}
                  fullWidth
                >
                  View Alerts
                </LinkButton>
              </Box>
            </Flex>
            <Flex direction="column" align="center" justify="center">
              <Icon type="resource" mb={4} size="large" />
              <Heading size="x-small" as="h4" mb={4}>
                Search through Resources
              </Heading>
              <Text fontSize="medium" color="gray-300" mb={6} maxWidth={275}>
                View your AWS resources and monitor their compliance with policies
              </Text>
              <Box width={225}>
                <LinkButton to={urls.compliance.resources.list()} fullWidth>
                  View Resources
                </LinkButton>
              </Box>
            </Flex>
            <Flex direction="column" align="center" justify="center">
              <Icon type="search" mb={4} size="large" />
              <Heading size="x-small" as="h4" mb={4}>
                Query Logs with Athena
              </Heading>
              <Text fontSize="medium" color="gray-300" mb={6} maxWidth={275}>
                Use AWS Athena to write complex queries against normalized log data
              </Text>
              <Box width={225}>
                <LinkButton
                  external
                  to={`https://${pantherConfig.AWS_REGION}.console.aws.amazon.com/athena/`}
                  fullWidth
                >
                  Launch Athena
                </LinkButton>
              </Box>
            </Flex>
          </SimpleGrid>
        </Card>
      </Box>
      <Box py={10}>
        <Box as="header" my={10} textAlign="center" fontWeight="medium">
          <Heading size="x-large" fontWeight="medium" mb={2}>
            The following links may be helpful
          </Heading>
          <Heading as="h2" size="x-small" fontWeight="medium" color="gray-300">
            We{"'"}ve got some things to make you stick around a little bit more.
          </Heading>
        </Box>
        <SimpleGrid columns={3} py={5} spacing={6}>
          <Card p={7} as="article" fontSize="medium">
            <Heading size="x-small" as="h4" mb={3}>
              Our Blog
            </Heading>
            <Text fontSize="medium" color="gray-300" mb={3}>
              Learn tips and best practices on how to keep your account safe
            </Text>
            <Link external py={4} href="http://blog.runpanther.io/">
              Visit our blog
            </Link>
          </Card>
          <Card p={7} as="article" fontSize="medium">
            <Heading size="x-small" as="h4" mb={3}>
              Panther Documentation
            </Heading>
            <Text fontSize="medium" color="gray-300" mb={3}>
              Learn more about Panther and how can you best harness its power to secure your
              business
            </Text>
            <Link external py={4} href={PANTHER_DOCS_LINK}>
              Discover Panther
            </Link>
          </Card>
          <Card p={7} as="article" fontSize="medium">
            <Heading size="x-small" as="h4" mb={3}>
              Need support?
            </Heading>
            <Text fontSize="medium" color="gray-300" mb={3}>
              Facing issues or want to learn more about Panther? Get in touch with us!
            </Text>
            <Link external py={4} href="mailto:contact@runpanther.io">
              Contact us
            </Link>
          </Card>
        </SimpleGrid>
      </Box>
    </FadeIn>
  );
};

export default withSEO({ title: 'Dashboard' })(LandingPage);
