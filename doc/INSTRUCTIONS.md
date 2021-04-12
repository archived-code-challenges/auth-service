# Golang authorisation

## Overview

The task is to write a small microservice to manage access to Users, the service should be implemented in either Java (Spring Boot) or Go - as these are the two primary languages that we use at FACEIT.

Each user entity must consist of a first name, last name, nickname, password, email and country.

The service must allow you to:

- Add a new User
- Modify an existing User
- Remove a User
- Return a list of the Users, allowing for filtering by certain criteria (e.g. all Users with the country "UK")

The service must include:

- A sensible storage mechanism for the Users
- The ability to send events to notify other interested services of changes to User entities

However, we do not expect a packaged and production ready solution for these issues, so the use of local alternatives (for instance a database containerised and linked to your service through docker-compose) or stubs is encouraged.

Remember that we want to test your understanding of these concepts, not how well you write boilerplate code. If your solution is becoming overly complex, simply explain what would have been implemented and prepare for follow-up questions in the technical interview.

Further to the practical workings of the service, we expect it to be a "good citizen" in our microservice architecture, it can achieve this by providing:

- Meaningful logs
- Self-documenting end points
- Health checks

Please also provide a README.md that contains:

- Instructions to start the application on localhost (dockerised applications are preferred)
- An explanation of the assumptions made during development
- Possible extensions or improvements to the service (focusing on scalability and deployment to production)

We expect to be able to run the tests, build the application and run it locally.
