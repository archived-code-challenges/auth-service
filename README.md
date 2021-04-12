# Golang authentication service

Thank you for giving me the opportunity to participate in the selection process, it has been a very enjoyable test.

## Technical decisions

- I have limitted authentication and is only used when **removing** a User resource. The middlewares will check if a user is authenticated and is removing resource of its own. Therefore, in order to remove a user through the API, you must authenticate with its credentials beforehand.

### External dependencies

- I have used [GORM](https://gorm.io) to manage the database transactions.
- And [go-chi](https://github.com/go-chi/chi) to extend some HTTP service attributes.

## Possible extensions or improvements

- When deploying to production, I would like to know if the number of requests for the service is very large, perhaps the trace service can slow down performance.
- I would extend authentication to use roles, in order to allow users to have specific permissions.
- I have been used the attributes active and settings as a good practice but they are not completely functional and with some more time I would extend their functionality.
- There are some things that have not been tested, the functionality is (overall) correct but with a little more time I would have ensured 90%+ coverage.
- The migration method could be extended to use previous states of the database.

### Data structure

- [Authentication](#authentication)
  - [With password](#with-password)
  - [With refresh token](#with-refresh-token)
- [User](#user)

### Authentication

#### With password

The request must be sent form-encoded, and the response will be sent JSON encoded.

**Request:**

    POST /api/oauth/login
    Content-Type: application/x-www-form-urlencoded

    grant_type=password
    &email=user@example.com
    &password=1234secret

Parameters:

- **grant_type**: Must be "password".
- **email**: User's email address.
- **password**: User's password.

#### With refresh token

The request must be sent form-encoded, and the response will be sent JSON encoded.

A token request using a refresh token will return a new, current access token as well as a new refresh token, extending the lifetime of the user session and reducing chances of the user needing to login again to the system, as long as the user access the system frequently.

**Request:**

    POST /api/oauth/login
    Content-Type: application/x-www-form-urlencoded

    grant_type=refresh_token
    &refresh_token=IwOGYzYTlmM2YxOTQ5MGE3YmNmMDFkNTVk

Parameters:

- **grant_type**: Must be "refresh_token".
- **refresh_token**: A previously issued refresh_token.

### User

A **User** resource represents a user of the system.

**Fields:**

| Field | Type | Default | Description |
| - | - | - | - |
| **id**                      | int    |      | User ID in the database. |
| **active**                  | bool   | true | Whether the account is active. An inactive account is not able to login to the application, or perform any actions via the API. |
| **country**                 | string |      | Country code on [ISO 3166-1 format](https://en.wikipedia.org/wiki/List_of_ISO_3166_country_codes). |
| **email**                   | string |      | User email address. Used for user identification, login. Is a **mandatory** field and **must be unique** in the application. |
| **firstName**, **lastName** | string |      | User name details. The first name is **mandatory.** |
| **nickname**                | string |      | User nickname. |
| **password**                | string |      | User password. **Must be passed on create/update operations**. It's never returned on any read operations. |
| **settings**                | string |  {}  | A string used to store user preferences like dark mode or similar profile data. |

## Instructions to run the project

If the host operating system is macOS:

    make compose-mac

If it is linux:

    make compose-linux

On a first startup, the database should be initialised by running

    go run ./cmd/admin/main.go migrate

After a successful execution, the service should be running on port 8080:

- [:8080](http://localhost:8080/)

Tracing can be found at:

- [:9411/zipkin/](http://localhost:9411/zipkin/)
- [:6060/debug/pprof/](http://localhost:6060/debug/pprof/)

![image-tracing-support](/doc/assets/tracing-support.png)

## API usage

The project has a [Postman collection](/doc/golang-authetication-service.postman_collection.json) attached, which can be used to interact with the authentication/user service.

### Packaging

    ├── cmd             # Entrypoint
    │   ├── admin       # Admin (database) related tasks and x509 key creator for the auth service
    │   └── api         # Main API
    ├── doc             # Documentation, images and helpful files
    └── internal
        ├── errors      # Utilities that make easier error handling throughout the project
        ├── handlers    # HTTP layer
        ├── middleware
        ├── models      # Business logic
        ├── schema      # Framework for common database related tasks
        └── web         # Framework for common HTTP related tasks

### Benchmarking

I have benchmarked the two most computationally-expensive points of the API: The PUT method and authentication.
Here are the results:

    ali --body-file=./doc/assets/ali-update.json --method=PUT http://localhost:8080/api/users/1

![bench-put-user.gif](/doc/assets/bench-put-user.gif)
> Benchmark: 50 requests per second. Max: 120~ ms

---

    ali --rate=10 --method=POST http://localhost:8080/oauth/login/bench/

![bench-auth.gif](/doc/assets/bench-auth.gif)
> Benchmark: 10 requests per second. Max: 728~ ms
