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
import { Box, Flex, Card, Icon, Text, Heading, SimpleGrid, Link } from 'pouncejs';
import { Link as RRLink } from 'react-router-dom';
import logo from 'Source/assets/panther-minimal-logo.svg';
import urls from 'Source/urls';
import { PANTHER_SCHEMA_DOCS_LINK } from 'Source/constants';

const LandingPage: React.FC = () => {
  return (
    <Box>
      <Box as="article">
        <Box my={60}>
          <Flex width={1} justify="center">
            <img src={logo} alt="Panther logo" width="60" height="60" />
          </Flex>
          <Heading as="h1" size="large" textAlign="center" color="grey500" mb={2} mt={5}>
            Welcome!
          </Heading>
          <Heading as="h2" size="medium" textAlign="center" color="grey300">
            Let{"'"}s get you started with Panther
          </Heading>
        </Box>
        <Card mb={6} as="section">
          <SimpleGrid columns={3} py={5}>
            <Flex direction="column" align="center" justify="center" px={10} py={5}>
              <Icon color="grey300" type="user" mb={4} size="large" />
              <Text size="large" as="h4" color="grey500" mb={4}>
                Invite your team
              </Text>
              <Text size="medium" as="p" color="grey300" textAlign="center" maxWidth={250}>
                Create users and get your team onboarded to Panther
              </Text>
              <Link color="blue300" p={4} as={RRLink} to={urls.settings.users()}>
                Manage Users
              </Link>
            </Flex>
            <Flex direction="column" justify="center" align="center" px={10} py={5}>
              <Icon color="grey300" type="infra-source" mb={4} size="large" />
              <Text size="large" as="h4" color="grey500" mb={4}>
                Setup Infrastructure Monitoring
              </Text>
              <Text size="medium" as="p" color="grey300" textAlign="center" maxWidth={250}>
                Connect AWS accounts, scan resources and detect misconfigurations
              </Text>
              <Link color="blue300" p={4} as={RRLink} to={urls.compliance.sources.create()}>
                Onboard an AWS account
              </Link>
            </Flex>
            <Flex direction="column" justify="center" align="center" px={10} py={5}>
              <Icon color="grey300" type="log-source" mb={4} size="large" />
              <Text size="large" as="h4" color="grey500" mb={4}>
                Setup your Log Sources
              </Text>
              <Text size="medium" as="p" color="grey300" textAlign="center" maxWidth={250}>
                Connect your log buckets and analyze data with rules
              </Text>
              <Link color="blue300" p={4} as={RRLink} to={urls.logAnalysis.sources.create()}>
                Connect S3 Buckets
              </Link>
            </Flex>
          </SimpleGrid>
        </Card>

        <Card mb={6} as="section">
          <SimpleGrid columns={3} py={5}>
            <Flex direction="column" align="center" justify="center" px={10} py={5}>
              <Icon color="grey300" type="output" mb={4} size="large" />
              <Text size="large" as="h4" color="grey500" mb={4}>
                Setup an Alert Destination
              </Text>
              <Text size="medium" as="p" color="grey300" textAlign="center" maxWidth={250}>
                Add destinations so Panther can notify you of policy and rule findings
              </Text>
              <Link color="blue300" p={4} as={RRLink} to={urls.settings.destinations()}>
                Setup Destinations
              </Link>
            </Flex>

            <Flex direction="column" align="center" justify="center" px={10} py={5}>
              <Icon color="grey300" type="policy" mb={4} size="large" />
              <Text size="large" as="h4" color="grey500" mb={4}>
                Write Infrastructure Policies
              </Text>
              <Text size="medium" as="p" color="grey300" textAlign="center" maxWidth={250}>
                Create Cloud Security policies to evaluate your AWS infrastructure
              </Text>
              <Link color="blue300" p={4} as={RRLink} to={urls.compliance.policies.create()}>
                Create a Policy
              </Link>
            </Flex>
            <Flex direction="column" align="center" justify="center" px={10} py={5}>
              <Icon color="grey300" type="rule" mb={4} size="large" />
              <Text size="large" as="h4" color="grey500" mb={4}>
                Write Log Detection Rules
              </Text>
              <Text size="medium" as="p" color="grey300" textAlign="center" maxWidth={250}>
                Create rules to evaluate your logs and trigger alerts on suspicious activity
              </Text>
              <Link color="blue300" p={4} as={RRLink} to={urls.logAnalysis.rules.create()}>
                Create a Rule
              </Link>
            </Flex>
          </SimpleGrid>
        </Card>
        <Card mb={6} as="section">
          <SimpleGrid columns={3} py={5}>
            <Flex direction="column" align="center" justify="center" px={10} py={5}>
              <Icon color="grey300" type="alert" mb={4} size="large" />
              <Text size="large" as="h4" color="grey500" mb={4}>
                Triage Alerts
              </Text>
              <Text size="medium" as="p" color="grey300" textAlign="center" maxWidth={250}>
                View all alerts generated by rules that ran against your logs
              </Text>
              <Link color="blue300" p={4} as={RRLink} to={urls.logAnalysis.alerts.list()}>
                View Alerts
              </Link>
            </Flex>
            <Flex direction="column" align="center" justify="center" px={10} py={5}>
              <Icon color="grey300" type="resource" mb={4} size="large" />
              <Text size="large" as="h4" color="grey500" mb={4}>
                Search through Resources
              </Text>
              <Text size="medium" as="p" color="grey300" textAlign="center" maxWidth={250}>
                View your AWS resources and monitor their compliance with policies
              </Text>
              <Link color="blue300" p={4} as={RRLink} to={urls.compliance.resources.list()}>
                View Resources
              </Link>
            </Flex>
            <Flex direction="column" align="center" justify="center" px={10} py={5}>
              <Icon color="grey300" type="search" mb={4} size="large" />
              <Text size="large" as="h4" color="grey500" mb={4}>
                Query Logs with Athena
              </Text>
              <Text size="medium" as="p" color="grey300" textAlign="center" maxWidth={250}>
                Use AWS Athena to write complex queries against normalized log data
              </Text>
              <Link
                external
                color="blue300"
                p={4}
                href={`https://${process.env.AWS_REGION}.console.aws.amazon.com/athena/`}
              >
                Launch Athena
              </Link>
            </Flex>
          </SimpleGrid>
        </Card>
      </Box>
      <Box borderTop="1px solid" borderColor="grey100" my={60}>
        <Box as="header" my={10}>
          <Heading as="h1" size="large" textAlign="center" color="grey500" mb={4}>
            The following links may be helpful
          </Heading>
          <Heading as="h2" size="medium" textAlign="center" color="grey300">
            We{"'"}ve got some things to make you stick around a little bit more.
          </Heading>
        </Box>
        <SimpleGrid columns={3} py={5} spacing={6}>
          <Card p={9} as="article">
            <Heading size="medium" color="grey500" as="h4" mb={3}>
              Our Blog
            </Heading>
            <Text size="medium" as="p" color="grey300" mb={3}>
              Learn tips and best practices on how to keep your account safe
            </Text>
            <Link external color="blue300" py={4} href="http://blog.runpanther.io/">
              Visit our blog
            </Link>
          </Card>
          <Card p={9} as="article">
            <Heading size="medium" color="grey500" as="h4" mb={3}>
              Panther Documentation
            </Heading>
            <Text size="medium" as="p" color="grey300" mb={3}>
              Learn more about Panther and how can you best harness its power to secure your
              business
            </Text>
            <Link external color="blue300" py={4} href={PANTHER_SCHEMA_DOCS_LINK}>
              Discover Panther
            </Link>
          </Card>
          <Card p={9} as="article">
            <Heading size="medium" color="grey500" as="h4" mb={3}>
              Need support?
            </Heading>
            <Text size="medium" as="p" color="grey300" mb={3}>
              Facing issues or want to learn more about Panther? Get in touch with us!
            </Text>
            <Link external color="blue300" py={4} href="mailto:contact@runpanther.io">
              Contact us
            </Link>
          </Card>
        </SimpleGrid>
      </Box>
    </Box>
  );
};

export default LandingPage;
