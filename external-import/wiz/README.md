# OpenCTI External Ingestion Connector Wiz

| Status            | Date       | Comment |
| ----------------- |------------| ------- |
| Filigran Verified | 2025-04-09 |    -    |

Table of Contents

- [OpenCTI External Ingestion Connector Wiz](#opencti-external-ingestion-connector-wiz)
  - [Introduction](#introduction)
  - [Installation](#installation)
    - [Requirements](#requirements)
  - [Configuration variables](#configuration-variables)
    - [OpenCTI environment variables](#opencti-environment-variables)
    - [Base connector environment variables](#base-connector-environment-variables)
    - [Connector extra parameters environment variables](#connector-extra-parameters-environment-variables)
  - [Deployment](#deployment)
    - [Docker Deployment](#docker-deployment)
    - [Manual Deployment](#manual-deployment)
  - [Usage](#usage)
  - [Behavior](#behavior)
  - [Debugging](#debugging)
  - [Additional information](#additional-information)

## Introduction

This connector imports data made publicly available by Wiz exposed at https://threats.wiz.io/.
The list of imported entities (with their relationships) :

- **Incidents** : A historical collection of past cloud security incidents and campaigns, offering insights into targeting patterns, initial access methods, and effective impact.

- **Actors** : Profiles of threat actors involved in cloud security incidents, shedding light on their potential motivations and victimology, to aid in risk assessment and threat modeling. NB: These can be modeled as either Threat Actor or Intrusion Set objects, depending on the configuration variable. See `threat_actor_as_intrusion_set` in [Configuration variables](#configuration-variables).

- **Techniques** : An overview of attack techniques used by threat actors in cloud security incidents, aligned with the MITRE ATT&CK matrix framework for additional context.

- **Tools** : Details on software utilized by threat actors in their activities targeting cloud environments, ranging from penetration testing utilities to bespoke malware.

- **Targeted Technologies** : Analysis of frequently targeted software found in cloud environments, noting their prevalence and any related incidents and techniques.

- **Defenses** : A corpus of cloud security measures that can serve to mitigate risks and prevent or detect attack techniques. Each mechanism is mapped to the MITRE D3FEND matrix.



## Installation

### Requirements

- OpenCTI Platform >= 6.3.8

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or
in `config.yml` (for manual deployment).

### OpenCTI environment variables

Below are the parameters you'll need to set for OpenCTI:

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
|---------------|------------|-----------------------------|-----------|------------------------------------------------------|
| OpenCTI URL   | url        | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | token      | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

### Base connector environment variables

Below are the parameters you'll need to set for running the connector properly:

| Parameter                     | config.yml                    | Docker environment variable         | Default         | Mandatory | Description                                                                                                   |
|-------------------------------|-------------------------------|-------------------------------------|-----------------|-----------|---------------------------------------------------------------------------------------------------------------|
| Connector ID                  | id                            | `CONNECTOR_ID`                      | /               | Yes       | A unique `UUIDv4` identifier for this connector instance.                                                     |
| Connector Type                | type                          | `CONNECTOR_TYPE`                    | EXTERNAL_IMPORT | Yes       | Should always be set to `EXTERNAL_IMPORT` for this connector.                                                 |
| Connector Name                | name                          | `CONNECTOR_NAME`                    |                 | Yes       | Name of the connector.                                                                                        |
| Connector Scope               | scope                         | `CONNECTOR_SCOPE`                   |                 | Yes       | The scope or type of data the connector is importing, either a MIME type or Stix Object.                      |
| Log Level                     | log_level                     | `CONNECTOR_LOG_LEVEL`               | info            | Yes       | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.                        |
| Duration Period               | duration_period               | `CONNECTOR_DURATION_PERIOD`         | /               | Yes       | Determines how often the connector should run.                                                                |
| Threat Actor as Intrusion-Set | threat_actor_as_intrusion_set | `WIZ_THREAT_ACTOR_AS_INTRUSION_SET` | False           | No        | Convert Threat Actor objects to Intrusion Set objects. Defaults to `False`.                                   |
| TLP Level                     | tlp_level                     | `WIZ_TLP_LEVEL`                     | "clear"         | No        | TLP level to set on imported entities (allowed values are ['white', 'green', 'amber', 'amber+strict', 'red']) |

## Deployment

### Docker Deployment

Before building the Docker container, you need to set the version of pycti in `requirements.txt` equal to whatever
version of OpenCTI you're running. Example, `pycti==5.12.20`. If you don't, it will take the latest version, but
sometimes the OpenCTI SDK fails to initialize.

Build a Docker Image using the provided `Dockerfile`.

Example:

```shell
# Replace the IMAGE NAME with the appropriate value
docker build . -t [IMAGE NAME]:latest
```

Make sure to replace the environment variables in `docker-compose.yml` with the appropriate configurations for your
environment. Then, start the docker container with the provided docker-compose.yml

```shell
docker compose up -d
# -d for detached
```

### Manual Deployment

Create a file `config.yml` based on the provided `config.yml.sample`.

Replace the configuration variables (especially the "**ChangeMe**" variables) with the appropriate configurations for
you environment.

Install the required python dependencies (preferably in a virtual environment):

```shell
pip3 install -r requirements.txt
```

Then, start the connector from recorded-future/src:

```shell
python3 main.py
```

## Usage

After Installation, the connector should require minimal interaction to use, and should update automatically at a regular interval specified in your `docker-compose.yml` or `config.yml` in `duration_period`.

However, if you would like to force an immediate download of a new batch of entities, navigate to:

`Data management` -> `Ingestion` -> `Connectors` in the OpenCTI platform.

Find the connector, and click on the refresh button to reset the connector's state and force a new
download of data by re-running the connector.

## Behavior

<!--
Describe how the connector functions:
* What data is ingested, updated, or modified
* Important considerations for users when utilizing this connector
* Additional relevant details
-->


## Debugging

The connector can be debugged by setting the appropiate log level.
Note that logging messages can be added using `self.helper.connector_logger,{LOG_LEVEL}("Sample message")`, i.
e., `self.helper.connector_logger.error("An error message")`.

<!-- Any additional information to help future users debug and report detailed issues concerning this connector -->

## Additional information

<!--
Any additional information about this connector
* What information is ingested/updated/changed
* What should the user take into account when using this connector
* ...
-->
