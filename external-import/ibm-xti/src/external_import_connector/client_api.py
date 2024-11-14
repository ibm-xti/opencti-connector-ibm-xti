from datetime import datetime
from typing import Any, Optional
import requests

from pycti import OpenCTIConnectorHelper, Identity as OpenCTIIdentity
from taxii2client.v21 import Server, as_pages
from stix2 import TAXIICollectionSource, Identity
from stix2.parsing import parse

from .config_variables import ConfigConnector


class ConnectorClient:
    __helper: OpenCTIConnectorHelper
    __session: requests.Session
    __taxii_server: Server
    __identity: Any

    def __init__(self, helper: OpenCTIConnectorHelper, config: ConfigConnector):
        """
        Initialize the client with necessary configurations
        """
        self.__helper = helper

        # Define basic auth for session
        self.__session = requests.Session()
        self.__session.auth = (config.taxii_user, config.taxii_pass)

        self.__taxii_server = Server(
            config.taxii_server_url, user=config.taxii_user, password=config.taxii_pass
        )

        self.__identity = self.__helper.api.identity.create(
            type="Organization",
            name="IBM X-Force",
            description="IBM X-Force Premier Threat Intelligence Services",
        )

    def _request_data(self, api_url: str, params=None):
        """
        Internal method to handle API requests
        :return: Response in JSON format
        """
        try:
            response = self.__session.get(api_url, params=params)

            self.__helper.connector_logger.info(
                "[API] HTTP Get Request to endpoint", {"url_path": api_url}
            )

            response.raise_for_status()
            return response

        except requests.RequestException as err:
            error_msg = "[API] Error while fetching data: "
            self.__helper.connector_logger.error(
                error_msg, {"url_path": {api_url}, "error": {str(err)}}
            )
            return None

    def get_collection_sources(self):
        sources: dict[str, TAXIICollectionSource] = {}

        for collection in self.__taxii_server.api_roots[0].collections:
            if collection.can_read:
                sources[collection.id] = TAXIICollectionSource(collection)

        return sources

    def __process_object(self, obj: Any, col_type: str, stix_objects: list[Any]):
        record_counter = 0

        try:
            obj["x_opencti_created_by_ref"] = self.__identity["standard_id"]
            stix_obj = parse(obj, allow_custom=True)
        except Exception as err:
            self.__helper.connector_logger.error(
                f"Something went wrong processing object '{obj['id']}':\n{str(err)}",
                {"error": str(err)},
            )
            raise RuntimeError("Error parsing STIX object") from err

        if stix_obj.get("type") == "report":
            record_counter += 1
            self.__helper.connector_logger.info(
                f"type = {stix_obj.get('type')}, id = {stix_obj.get('id')}, name={stix_obj.get('name')}"
            )
            for ref in stix_obj.get("object_refs"):
                self.__helper.connector_logger.info(f"        reference = {ref}")
        else:
            if col_type != "report":
                record_counter += 1

            if stix_obj.get("type") == "indicator":
                self.__helper.connector_logger.info(
                    f"        type = {stix_obj.get('type')}, id = {stix_obj.get('id')}, pattern={stix_obj.get('pattern')}"
                )
            else:
                self.__helper.connector_logger.info(
                    f"        type = {stix_obj.get('type')}, id = {stix_obj.get('id')}"
                )

        stix_objects.append(stix_obj)

        return record_counter

    def get_latest_stix_objects(
        self, source: TAXIICollectionSource, added_after: Optional[str]
    ):
        """
        If params is None, retrieve all CVEs in National Vulnerability Database
        :param params: Optional Params to filter what list to return
        :return: A list of dicts of the complete collection of CVE from NVD
        """
        try:
            collection = source.collection

            message = f"Retrieving data from collection '{collection.title}' ({collection.id})"
            if added_after:
                message += f" since {added_after}"
            self.__helper.connector_logger.info(message)

            page_counter = 0
            record_counter = 0

            for page in as_pages(
                collection.get_objects,
                per_request=50,
                added_after=added_after,
            ):
                stix_objects = []
                max_new_added_after = 0.0

                page_counter += 1
                objects = page["objects"]
                self.__helper.connector_logger.info(
                    f"Processing {len(objects)} objects from page {page_counter} for collection '{collection.title}'"
                )

                for obj in objects:
                    record_counter += self.__process_object(
                        obj, collection.custom_properties["type"], stix_objects
                    )

                    record_timestamp = obj.get("modified") or obj.get("created")
                    if record_timestamp:
                        record_secs = datetime.fromisoformat(
                            record_timestamp
                        ).timestamp()
                    else:
                        record_secs = datetime.now().timestamp()

                    max_new_added_after = max(max_new_added_after, record_secs)

                yield stix_objects, datetime.fromtimestamp(
                    max_new_added_after or datetime.now().timestamp()
                ).strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception as err:
            self.__helper.connector_logger.error(
                f"Something went wrong retrieving data from collection '{collection.title}':\n{str(err)}",
                {"error": str(err)},
            )

        self.__helper.connector_logger.info(
            f"Finished retrieving data from collection '{collection.title}'. Total objects processed: {record_counter}"
        )
