package api

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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

// DO NOT EDIT! generated by mage
var cloudsecTemplate = `# Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
# Copyright (C) 2020 Panther Labs Inc
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

AWSTemplateFormatVersion: 2010-09-09
Description: IAM roles for an account being scanned by Panther.

Metadata:
  Version: v1.0.0

Mappings:
  # DO NOT EDIT PantherParameters section. Panther application relies on the exact format (including comments)
  # in order to replace the default values with an appropriate ones.
  PantherParameters:
    MasterAccountId:
      Value: '' # MasterAccountId
    MasterAccountRegion:
      Value: '' # MasterAccountRegion
    DeployCloudWatchEventSetup:
      Value: '' # DeployCloudWatchEventSetup
    DeployRemediation:
      Value: '' # DeployRemediation

Parameters:
  # Required parameters
  MasterAccountId:
    Type: String
    Description: DO NOT EDIT MANUALLY! Parameter is already populated with the appropriate value.
    Default: '' # MasterAccountId
  MasterAccountRegion:
    Type: String
    Description: DO NOT EDIT MANUALLY! Parameter is already populated with the appropriate value.
    Default: '' # MasterAccountRegion

  # Deployment toggles
  DeployCloudWatchEventSetup:
    Type: String
    Description: DO NOT EDIT MANUALLY! Parameter is already populated with the appropriate value.
    Default: ''
  DeployRemediation:
    Type: String
    Description: DO NOT EDIT MANUALLY! Parameter is already populated with the appropriate value.
    Default: ''

Conditions:
  # Condition to define if the template is generated by panther backend
  GeneratedTemplate: !Not [!Equals ['', !FindInMap [PantherParameters, MasterAccountId, Value]]]

  # Condition whether the generated template has CW events setup
  GeneratedCloudWatchEventSetup:
    !Equals [true, !FindInMap [PantherParameters, DeployCloudWatchEventSetup, Value]]
  # Condition whether the generated template has auto remediation setup
  GeneratedAutoRemediation: !Equals [true, !FindInMap [PantherParameters, DeployRemediation, Value]]

  # Condition whether the default template values configure CW events setup
  DefaultCloudWatchEventSetup: !Equals [true, !Ref DeployCloudWatchEventSetup]
  # Condition whether the default template values configure auto remediation
  DefaultAutoRemediation: !Equals [true, !Ref DeployRemediation]

  # Condition whether we should enable CWE
  EnableCloudWatchEvent: !Or
    - !And [Condition: GeneratedTemplate, Condition: GeneratedCloudWatchEventSetup]
    - !And [!Not [Condition: GeneratedTemplate], Condition: DefaultCloudWatchEventSetup]
  # Condition whether we should enable auto remediation
  EnableAutoRemediation: !Or
    - !And [Condition: GeneratedTemplate, Condition: GeneratedAutoRemediation]
    - !And [!Not [Condition: GeneratedTemplate], Condition: DefaultAutoRemediation]

Resources:
  AuditRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Sub PantherAuditRole-${MasterAccountRegion} # DO NOT CHANGE! backend.yml CF depends on this name
      Description: The Panther master account assumes this role for read-only security scanning
      AssumeRolePolicyDocument:
        Version: 2012-10-17
        Statement:
          - Effect: Allow
            Principal:
              AWS: !If
                - GeneratedTemplate
                - !Sub
                  - 'arn:${Partition}:iam::${Mapping}:root'
                  - Partition: !Ref AWS::Partition
                    Mapping: !FindInMap [PantherParameters, MasterAccountId, Value]
                - !Sub arn:${AWS::Partition}:iam::${MasterAccountId}:root
            Action: sts:AssumeRole
            Condition:
              Bool:
                aws:SecureTransport: true
      ManagedPolicyArns:
        - !Sub arn:${AWS::Partition}:iam::aws:policy/SecurityAudit
      Policies:
        - PolicyName: CloudFormationStackDriftDetection
          PolicyDocument:
            Version: 2012-10-17
            Statement:
              - Effect: Allow
                Action:
                  - cloudformation:DetectStackDrift
                  - cloudformation:DetectStackResourceDrift
                Resource: '*'
        - PolicyName: CloudFormationStackDriftDetectionSupplements
          # These permissions are not directly required for scanning, but are required by AWS in
          # order to perform CloudFormation Stack drift detection on the corresponding resource types
          PolicyDocument:
            Version: 2012-10-17
            Statement:
              - Effect: Allow
                Action:
                  - sns:ListTagsForResource
                  - lambda:GetFunction
                  - apigateway:GET
                Resource: '*'
        - PolicyName: GetWAFACLs
          PolicyDocument:
            Version: 2012-10-17
            Statement:
              - Effect: Allow
                Action:
                  - waf:GetRule
                  - waf:GetWebACL
                  - waf-regional:GetRule
                  - waf-regional:GetWebACL
                  - waf-regional:GetWebACLForResource
                Resource: '*'
        - PolicyName: GetTags
          PolicyDocument:
            Version: 2012-10-17
            Statement:
              - Effect: Allow
                Action:
                  - dynamodb:ListTagsOfResource
                  - kms:ListResourceTags
                  - waf:ListTagsForResource
                  - waf-regional:ListTagsForResource
                Resource: '*'
      Tags:
        - Key: Application
          Value: Panther

  CloudFormationStackSetExecutionRole:
    Condition: EnableCloudWatchEvent
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Sub PantherCloudFormationStackSetExecutionRole-${MasterAccountRegion} # DO NOT CHANGE!
      Description: CloudFormation assumes this role to execute a stack set
      AssumeRolePolicyDocument:
        Version: 2012-10-17
        Statement:
          - Effect: Allow
            Principal:
              AWS: !If
                - GeneratedTemplate
                - !Sub
                  - 'arn:${Partition}:iam::${Mapping}:root'
                  - Partition: !Ref AWS::Partition
                    Mapping: !FindInMap [PantherParameters, MasterAccountId, Value]
                - !Sub arn:${AWS::Partition}:iam::${MasterAccountId}:root
            Action: sts:AssumeRole
      Policies:
        - PolicyName: ManageCloudFormationStack
          PolicyDocument:
            Version: 2012-10-17
            Statement:
              - Effect: Allow
                Action: cloudformation:*
                Resource: '*'
        - PolicyName: PantherSetupRealTimeEvents
          PolicyDocument:
            Version: 2012-10-17
            Statement:
              - Effect: Allow
                Action:
                  - events:*
                  - sns:*
                Resource: '*'
      Tags:
        - Key: Application
          Value: Panther

  RemediationRole:
    Condition: EnableAutoRemediation
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Sub PantherRemediationRole-${MasterAccountRegion} # DO NOT CHANGE! backend.yml CF depends on this name
      Description: The Panther master account assumes this role for automatic remediation of policy violations
      MaxSessionDuration: 3600 # 1 hour
      AssumeRolePolicyDocument:
        Version: 2012-10-17
        Statement:
          - Effect: Allow
            Principal:
              AWS: !If
                - GeneratedTemplate
                - !Sub
                  - 'arn:${Partition}:iam::${Mapping}:root'
                  - Partition: !Ref AWS::Partition
                    Mapping: !FindInMap [PantherParameters, MasterAccountId, Value]
                - !Sub arn:${AWS::Partition}:iam::${MasterAccountId}:root
            Action: sts:AssumeRole
            Condition:
              Bool:
                aws:SecureTransport: true
      Policies:
        - PolicyName: AllowRemediativeActions
          PolicyDocument:
            Version: 2012-10-17
            Statement:
              - Effect: Allow
                Action:
                  - cloudtrail:CreateTrail
                  - cloudtrail:StartLogging
                  - cloudtrail:UpdateTrail
                  - dynamodb:UpdateTable
                  - ec2:CreateFlowLogs
                  - ec2:StopInstances
                  - ec2:TerminateInstances
                  - guardduty:CreateDetector
                  - iam:CreateAccessKey
                  - iam:CreateServiceLinkedRole
                  - iam:DeleteAccessKey
                  - iam:UpdateAccessKey
                  - iam:UpdateAccountPasswordPolicy
                  - kms:EnableKeyRotation
                  - logs:CreateLogDelivery
                  - rds:ModifyDBInstance
                  - rds:ModifyDBSnapshotAttribute
                  - s3:PutBucketAcl
                  - s3:PutBucketPublicAccessBlock
                  - s3:PutBucketVersioning
                  - s3:PutBucketLogging
                  - s3:PutEncryptionConfiguration
                Resource: '*'
      Tags:
        - Key: Application
          Value: Panther

Outputs:
  CloudFormationStackSetExecutionRoleArn:
    Condition: EnableCloudWatchEvent
    Description: The Arn of the CloudFormation StackSet Execution Role for configuring Panther infra.
    Value: !GetAtt CloudFormationStackSetExecutionRole.Arn
  PantherRemediationRoleArn:
    Condition: EnableAutoRemediation
    Description: The Arn of the Panther Auto Remediation IAM Role
    Value: !GetAtt RemediationRole.Arn
`
