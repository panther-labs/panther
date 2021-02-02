---
name: RFC
about: A request for comments doc to detail implementation of a new Epic
title: '[RFC] Title of Feature'
labels: rfc
assignees: ''
---

# What and Why

What is the feature in one sentence?

What is the motivating force for this RFC? Explain the problems Panther customers or Panther itself has faced that this RFC will address. Be specific and add enough context for anyone in the team to understand.

## Benefits

How will Panther customers or the Panther platform itself benefit from this?

## Costs and Risks

> **_NOTE:_** This section may not be applicable to some RFCs.

Are there costs or risks in doing this or NOT doing this? For example, if the RFC addresses technical debt, there may be both costs and risks for NOT addressing the need.

You may not be able to quantify costs, however, if there is the expectation of significant costs then you should identify the areas and reasons.

# Approach

How are we planning to solve this problem on a technical level? You should address the following areas as appropriate:

- Scaling behavior and overall dimensions (data, compute, network, etc)
- Availability considerations
- Error handling
- Deployment and data migrations
- Maintainability/complexity
- Are there single points of failure? If so, what are the mitigations? If we lose all/part of this subsystem, how do we recover state?

You should also suggest multiple solutions and compare them below.

## Proposal: Option 1

Technical implementation number 1

## Proposal: Option 2

Technical implementation number 2

# API

> **_NOTE:_** Include Mock and realistic data in the response

| Service Name | Endpoint | Request Parameters | Response |
| ------------ | -------- | ------------------ | -------- |
|              |          |                    |          |
|              |          |                    |          |
|              |          |                    |          |

# Security Considerations

> **_NOTE:_** Required! Do not leave this out

- How will this feature affect the security of Panther?
- Are there secrets or sensitive user information involved?
- Is least privilege followed? List out the precautions taken

# Effort

Estimated story points for frontend, backend, and design.
