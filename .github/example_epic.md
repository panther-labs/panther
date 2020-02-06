# Example: Programmatic Policy & Rule Updates

## Introduction

Today, teams use the `panther-cli` to locally test and create analysis packages that are then uploaded via the UI.

To better accommodate automated workflows when developing Rules and Policies, teams need an easier way to push into Panther directly.

## Product requirements

1. A user can type `panther-cli update` to upload the latest Rules and Policies
2. A user can decide which analysis type to upload with filters
3. A user can decide which base path to upload from

## Technical requirements

Engineering Requirements:

1. Add a new command to the `panther-cli` to access the Lambda endpoint directly
2. Set a bit on the backend indicating the policy was uploaded and not created in the UI

## Design requirements (optional)

1. Show an info banner in the rule/policy editor UI indicating it was either uploaded or created in the UI

## User Stories

[ ] TODO
